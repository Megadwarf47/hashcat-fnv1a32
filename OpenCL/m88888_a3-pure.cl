#define NEW_SIMD_CODE
#define OPT1

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#endif

// Define the constants for 32-bit FNV-1a hash
#define FNV32_OFFSET_BASIS 0x811C9DC5
#define FNV32_PRIME         0x01000193

KERNEL_FQ void m88888_mxx (KERN_ATTR_VECTOR ())
{
    /**
     * modifier
     */

    const u64 gid = get_global_id (0);

    if (gid >= gid_max) return;

    /**
     * base
     */

    const u32 pw_len = pws[gid].pw_len;

    u32 w[64] = { 0 };

    for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
    {
        w[idx] = pws[gid].i[idx];
    }

    /**
     * loop
     */

    u32 w0l = w[0];

    for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
    {
        const u32 w0r = words_buf_r[il_pos / VECT_SIZE];

        const u32 w0 = w0l | w0r;

        w[0] = w0;

        u32 num = FNV32_OFFSET_BASIS;

        u8 *p = (u8 *)(w);

        for (u32 i = 0; i < pw_len; i++)
        {
            num ^= (p[i]);
#ifdef OPT1
            num += (num << 1) + (num << 4) + (num << 5) + (num << 7) + (num << 8) + (num << 40);
#else
            num *= FNV32_PRIME;
#endif
        }

        const u32 r0 = num;  // The final hash is the result

        COMPARE_M_SIMD_2 (r0, 0, 0, 0);  // Compare only r0 in 32-bit
    }
}

KERNEL_FQ void m88888_sxx (KERN_ATTR_VECTOR ())
{
    /**
     * modifier
     */

    const u64 gid = get_global_id (0);

    if (gid >= gid_max) return;

    /**
     * digest
     */

    const u32 search[4] =
    {
        digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R0],
        digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R1],
        0,
        0
    };

    /**
     * base
     */

    const u32 pw_len = pws[gid].pw_len;

    u32 w[64] = { 0 };

    for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
    {
        w[idx] = pws[gid].i[idx];
    }

    /**
     * loop
     */

    u32 w0l = w[0];

    for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
    {
        const u32 w0r = words_buf_r[il_pos / VECT_SIZE];

        const u32 w0 = w0l | w0r;

        w[0] = w0;

        u32 num = FNV32_OFFSET_BASIS;

        u8 *p = (u8 *)(w);

        for (u32 i = 0; i < pw_len; i++)
        {
            num ^= (p[i]);
#ifdef OPT1
            num += (num << 1) + (num << 4) + (num << 5) + (num << 7) + (num << 8) + (num << 40);
#else
            num *= FNV32_PRIME;
#endif
        }

        const u32 r0 = num;

        COMPARE_S_SIMD_2 (r0, 0, 0, 0);  // Compare only r0 in 32-bit
    }
}
