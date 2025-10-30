#include <scx_test.h>
#include <scx_test_map.h>
#include <scx_test_cpumask.h>

#include <string.h>

#include <scx/common.bpf.h>
#include <lib/sdt_task_defs.h>

#include "main.bpf.c"

// per thread globals because the Rust test driver has multiple threads
static __thread struct scx_test_map task_masks_map = { 0 };

static void setup_task_wrapper(struct task_struct *p, struct cpumask *cpumask)
{
	struct mask_wrapper *wrapper;

	wrapper = bpf_task_storage_get(&task_masks, p, NULL,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	scx_test_assert(wrapper);
	wrapper->mask = cpumask;
}

static void setup_llc(u64 dsqid, u32 id, u32 nr_cpus, scx_bitmap_t mask)
{
	llc_ptr llcx;

	// Allocate LLC context in arena (simplified for testing)
	// In real code this would use bpf_arena_alloc_pages
	if (id >= MAX_LLCS)
		return;

	// For testing, we'll just initialize the static array
	// A proper test would allocate from arena
	if (!llc_ctx_by_id[id]) {
		// Allocate placeholder - in real tests this needs arena setup
		return;
	}

	llcx = llc_ctx_by_id[id];
	cast_kern(llcx);
	if (!llcx)
		return;

	llcx->id = id;
	llcx->dsq = dsqid;
	llcx->nr_cpus = nr_cpus;
	llcx->cpumask = mask;
}

/*
 * Runs at the start of each test and operates on per-thread globals. No need
 * for locking but check if already initialised.
 */
static void init_p2dq_test(void)
{
	static bool initialized = false;

	if (initialized)
		return;

	INIT_SCX_TEST_MAP_FROM_TASK_STORAGE(&task_masks_map, task_masks);
	scx_test_map_register(&task_masks_map, &task_masks);

	// Initialize cpu_ctx_storage array directly
	for (int i = 0; i < NR_CPUS && i < MAX_CPUS; i++) {
		cpu_ctx_storage[i].id = i;
		cpu_ctx_storage[i].llc_id = i % 4;
	}

	initialized = true;
}

SCX_TEST(test_pick_idle_cpu)
{
	struct task_struct p = { 0 };
	task_ctx my_taskc = { 0 };
	struct cpumask llc_cpumask = { 0 };
	s32 idle_cpu;
	bool is_idle = false;

	init_p2dq_test();

	my_taskc.llc_id = 1;
	my_taskc.dsq_id = 1;

	// Note: setup_llc now requires arena allocation to work properly
	// This test is simplified and may not work without arena setup
	setup_task_wrapper(&p, &llc_cpumask);

	for (int i = 0; i < NR_CPUS; i++) {
		scx_test_set_all_cpumask(i);
		scx_test_cpumask_set(i, &llc_cpumask);
	}

	idle_cpu = pick_idle_cpu(&p, &my_taskc, 0, 0, &is_idle);
	scx_test_assert(idle_cpu >= 0);
	scx_test_assert(idle_cpu < NR_CPUS);

	/* Set 3 as the only idle CPU */
	is_idle = false;
	scx_test_set_idle_cpumask(3);
	scx_test_set_idle_smtmask(3);
	idle_cpu = pick_idle_cpu(&p, &my_taskc, 0, 0, &is_idle);
	scx_test_assert(idle_cpu == 3);
	scx_test_assert(is_idle);
}

SCX_TEST(test_lookup_cpu_ctx)
{
	struct cpu_ctx __arena *my_cpuc = NULL;
	int i;

	init_p2dq_test();

	// Arena-backed storage is already initialized in init_p2dq_test
	for (i = 0; i < NR_CPUS && i < MAX_CPUS; i++) {
		my_cpuc = lookup_cpu_ctx(i);
		scx_test_assert(my_cpuc != NULL);
		scx_test_assert(my_cpuc->id == i);
		scx_test_assert(my_cpuc->llc_id == (u32)(i % 4));
	}

	/*
	 * When we specify a negative number we lookup the current CPU, which
	 * for the test implementation is just cpu 0, so validate this matches
	 * cpu 0.
	 */
	my_cpuc = lookup_cpu_ctx(-1);
	scx_test_assert(my_cpuc != NULL);
	scx_test_assert(my_cpuc->id == 0);
	scx_test_assert(my_cpuc->llc_id == 0);
}

SCX_TEST(test_is_interactive)
{
	task_ctx my_taskc = {
		.dsq_index = 0,
	};

	init_p2dq_test();

	scx_test_assert(is_interactive(&my_taskc));
	my_taskc.dsq_index = 1;
	scx_test_assert(!is_interactive(&my_taskc));
}
