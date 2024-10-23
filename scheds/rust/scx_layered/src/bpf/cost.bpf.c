/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


struct layer_cost {
	int		budget[MAX_LAYERS];
	int		capacity[MAX_LAYERS];
	u64		last_update;
	bool		has_parent;
	bool		overflow;
	struct bpf_spin_lock	lock;
};


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct token_bucket);
	__uint(max_entries, MAX_NUMA_NODES * MAX_LLCS * MAX_LAYERS);
	__uint(map_flags, 0);
} layer_cost_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct token_bucket);
	__uint(max_entries, 1);
} cpu_layer_cost_data SEC(".maps");



static struct layer_cost *lookup_cost(u32 cost_id)
{
	struct layer_cost *lcost;

	lcost = bpf_map_lookup_elem(&layer_cost_data, &cost_id);

	return lcost;
}

static struct layer_cost *lookup_cpu_layer_cost(s32 cpu)
{
	struct layer_cost *lcost;
	u32 zero = 0;

	if (cpu < 0)
		lcost = bpf_map_lookup_elem(&cpu_layer_cost_data, &zero);
	else
		lcost = bpf_map_lookup_percpu_elem(&cpu_layer_cost_data, &zero, cpu);

	return lcost;
}


static __always_inline void record_cpu_cost(struct layer_cost *lcost, s32 layer_id, int cost)
{
	lcost->budget[layer_id] -= cost;
}

static void refresh_layer_budget(int key, int layer_idx, int amount)
{
	struct layer_cost *lcost;

	lcost = bpf_map_lookup_elem(&layer_cost_data, &key);

	lcost->budget[layer_idx] += amount;
}


static int layer_refresh_budget(int idx)
{
	return 0;
}

static bool refresh_budgets(void)
{
	int layer_idx, amount;
	int key = 0; // global budget

	trace("TIMER refreshing budgets");
	bpf_for(layer_idx, 0, nr_layers) {
		amount = layer_refresh_budget(layer_idx);
		refresh_layer_budget(key, layer_idx, amount);
	}

	return true;
}
