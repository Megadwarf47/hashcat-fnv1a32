KERNEL_FQ void m88888_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 num = 2166136261UL;  // 32-bit FNV-1a initial value

    u8 *p = (u8 *)tmp.i;

    for (u32 i = 0; i < tmp.pw_len; i++)
    {
      num ^= (p[i]);           // XOR the current byte
      num *= 16777619;         // Multiply by the 32-bit FNV-1a prime
    }

    const u32 r0 = num;  // Directly use the 32-bit result
    const u32 r1 = 0;    // No second part for 32-bit hash
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_M_SCALAR_2 (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m88888_sxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 num = 2166136261UL;  // 32-bit FNV-1a initial value

    u8 *p = (u8 *)tmp.i;

    for (u32 i = 0; i < tmp.pw_len; i++)
    {
      num ^= (p[i]);           // XOR the current byte
      num *= 16777619;         // Multiply by the 32-bit FNV-1a prime
    }

    const u32 r0 = num;  // Directly use the 32-bit result
    const u32 r1 = 0;    // No second part for 32-bit hash
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_S_SCALAR_2 (r0, r1, r2, r3);
  }
}
