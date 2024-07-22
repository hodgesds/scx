/* to be included in the main bpf.c file */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "intf.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, char[MAX_ENV_SIZE]);
} env_var_tmp SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	/* double size because verifier can't follow length calculation */
	__uint(value_size, 2 * MAX_PATH);
	__uint(max_entries, 1);
} cgrp_path_bufs SEC(".maps");

struct env_ctx {
	const char* env;
	const char* key;
	u32 key_len;
	u32 loc;
	u32 len;
	u32 curr;
};

static char *format_cgrp_path(struct cgroup *cgrp)
{
	u32 zero = 0;
	char *path = bpf_map_lookup_elem(&cgrp_path_bufs, &zero);
	u32 len = 0, level, max_level;

	if (!path) {
		scx_bpf_error("cgrp_path_buf lookup failed");
		return NULL;
	}

	max_level = cgrp->level;
	if (max_level > 127)
		max_level = 127;

	bpf_for(level, 1, max_level + 1) {
		int ret;

		if (level > 1 && len < MAX_PATH - 1)
			path[len++] = '/';

		if (len >= MAX_PATH - 1) {
			scx_bpf_error("cgrp_path_buf overflow");
			return NULL;
		}

		ret = bpf_probe_read_kernel_str(path + len, MAX_PATH - len - 1,
						BPF_CORE_READ(cgrp, ancestors[level], kn, name));
		if (ret < 0) {
			scx_bpf_error("bpf_probe_read_kernel_str failed");
			return NULL;
		}

		len += ret - 1;
	}

	if (len >= MAX_PATH - 2) {
		scx_bpf_error("cgrp_path_buf overflow");
		return NULL;
	}
	path[len] = '/';
	path[len + 1] = '\0';

	return path;
}

static inline bool match_prefix(const char *prefix, const char *str, u32 max_len)
{
	int c;

	bpf_for(c, 0, max_len) {
		if (prefix[c] == '\0')
			return true;
		if (str[c] != prefix[c])
			return false;
	}
	return false;
}

static long env_get_len(u32 index, struct env_ctx* ctx) {
	u32 off = ctx->loc + index;
	if (off >= MAX_ENV_SIZE) {
		return 1;
	}

	const char* ptr = ctx->env + off;
	if (*ptr == '\0') {
		ctx->len = index;
		return 1;
	}

	return 0;
}

static long match_env_key(u32 index, struct env_ctx* ctx) {
	u32 off = ctx->curr + index;
	if (off >= MAX_ENV_SIZE || index >= ctx->key_len ||
	    index >= ENV_KEY_SIZE) {
		return 1;
	}

	if (ctx->env[off] != ctx->key[index] || ctx->key[index] == '\0') {
		if (ctx->env[off] == '=' && ctx->key[index] == '\0') {
			ctx->loc = off + 1;
			ctx->len = 0;
			bpf_loop(ENV_VAL_SIZE, &env_get_len, ctx, 0);
		}
	return 1;
	}

	return 0;
}

static long match_env(u32 index, struct env_ctx* ctx) {
	if (index >= MAX_ENV_SIZE || ctx->loc) {
		// We're at the end or we've already found a match
		return 1;
	}

	if (index != 0) {
		u32 off = index - 1;
		off &= ENV_SIZE_MASK;
		if (ctx->env[off] != '\0') {
			// Only try to match start of keys
			return 0;
		}
	}

	u32 rem = MAX_ENV_SIZE - index - 2;
	if (rem < ctx->key_len) {
		return 1;
	}

	ctx->curr = index;
	bpf_loop(ctx->key_len, &match_env_key, ctx, 0);
	if (ctx->loc) {
		return 1;
	}

	return 0;
}

static void get_env_value(const char* env, const char* key, size_t key_len, char* dst)
{
	struct env_ctx ctx = {
		.env = env,
		.key = key,
		.key_len = key_len,
		.loc = 0,
		.len = 0,
		.curr = 0,
	};

	bpf_loop(MAX_ENV_SIZE, &match_env, &ctx, 0);

	if (ctx.len) {
		ctx.len &= ENV_VAL_SIZE_MASK;
		ctx.loc &= ENV_SIZE_MASK;
		bpf_probe_read(dst, ctx.len, ctx.env + ctx.loc);
	}
}

static void get_env_var_from_task(struct task_struct* task, const char* key,
				  size_t key_len, char* dst)
{
	void* env_start = (char*)BPF_CORE_READ(task, mm, env_start);
	void* env_end = (char*)BPF_CORE_READ(task, mm, env_end);
	if (!env_start || !env_end)
		goto end;

	size_t env_length = env_end - env_start;
	env_length = env_length < MAX_ENV_SIZE - 1 ? env_length : MAX_ENV_SIZE - 1;

	__u32 zero = 0;
	char* env = bpf_map_lookup_elem(&env_var_tmp, &zero);
	if (!env)
		goto end;

	if (bpf_probe_read_user(env, env_length, env_start))
		goto end;

	get_env_value(env, key, key_len, dst);
	return;

end:
	  *dst = '\0';
}
