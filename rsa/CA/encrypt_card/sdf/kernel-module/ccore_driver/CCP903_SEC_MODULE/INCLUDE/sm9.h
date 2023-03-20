#ifndef __SM9__
#define __SM9__

struct sm9_point_dma {
  unsigned long long x;
  unsigned long long y;
};

struct sm9_ecc_dma {
  unsigned long long   q;
  unsigned long long   a;
  unsigned long long   b;
  unsigned long long   n;
  struct sm9_point_dma p1;
  struct sm9_point_dma p2;
};

struct sm9_const_value {
  unsigned int v;
  unsigned int len;
  unsigned int hlen;
  unsigned int dlen;
};

struct sm9_ciphertext_dma {
  unsigned long long c1;
  unsigned long long c2;
  unsigned long long c3;
};

struct sm9_signature_dma {
  unsigned long long h;
  unsigned long long s;
};

struct sm9_genmastkey_for_enc_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  unsigned long long     desc_dma;
  unsigned long long     ke_dma;
  struct sm9_point_dma   ppub_e;

  unsigned char rng_mode;
};

struct sm9_genusekey_for_enc_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  unsigned long long     desc_dma;
  unsigned long long     ke_dma;
  unsigned long long     hashin_dma;
  unsigned long long     one_dma;
  unsigned long long     idb_dma;
  unsigned long long     hid_dma;
  unsigned long long     hashout_dma;
  struct sm9_point_dma   deb;

  unsigned int  entlb;
  unsigned char endian_mode;
};

struct sm9_genkey_for_enc_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  unsigned long long     desc_dma;
  unsigned long long     ke_dma;
  struct sm9_point_dma   ppub_e;
  unsigned long long     hashin_dma;
  unsigned long long     one_dma;
  unsigned long long     idb_dma;
  unsigned long long     hid_dma;
  unsigned long long     hashout_dma;
  struct sm9_point_dma   deb;

  unsigned int  entlb;
  unsigned char rng_mode;
  unsigned char endian_mode;
};

struct sm9_genmastkey_for_sig_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  unsigned long long     desc_dma;
  unsigned long long     ks_dma;
  struct sm9_point_dma   ppub_s;

  unsigned char rng_mode;
};

struct sm9_genusekey_for_sig_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  unsigned long long     desc_dma;
  unsigned long long     ks_dma;
  unsigned long long     hashin_dma;
  unsigned long long     one_dma;
  unsigned long long     ida_dma;
  unsigned long long     hid_dma;
  unsigned long long     hashout_dma;
  struct sm9_point_dma   dsa;

  unsigned int  entla;
  unsigned char endian_mode;
};

struct sm9_genkey_for_sig_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  unsigned long long     desc_dma;
  unsigned long long     ks_dma;
  struct sm9_point_dma   ppub_s;
  unsigned long long     hashin_dma;
  unsigned long long     one_dma;
  unsigned long long     ida_dma;
  unsigned long long     hid_dma;
  unsigned long long     hashout_dma;
  struct sm9_point_dma   dsa;

  unsigned int  entla;
  unsigned char rng_mode;
  unsigned char endian_mode;
};

struct sm9_genkey_for_exc_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  unsigned long long     desc_dma;
  unsigned long long     ke_dma;
  struct sm9_point_dma   ppub_e;
  unsigned long long     hashin_dma;
  unsigned long long     one_dma;
  unsigned long long     ida_dma;
  unsigned long long     idb_dma;
  unsigned long long     hid_dma;
  unsigned long long     hashout_dma;
  struct sm9_point_dma   dea;
  struct sm9_point_dma   deb;

  unsigned int  entla;
  unsigned int  entlb;
  unsigned char rng_mode;
  unsigned char endian_mode;
};

struct sm9_encapkey_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  unsigned long long     desc_dma;
  unsigned long long     hashin_dma;
  unsigned long long     one_dma;
  unsigned long long     idb_dma;
  unsigned long long     hid_dma;
  unsigned long long     hashout_dma;
  struct sm9_point_dma   ppub_e;
  unsigned long long     r_dma;
  unsigned long long     c_dma;

  unsigned long long dsaa1_dma;
  unsigned long long t_xs_dma;
  unsigned long long t_ys_dma;
  unsigned long long t_zs_dma;
  unsigned long long zero_dma;
  unsigned long long key_dma;
  unsigned long long p12r_dma;
  unsigned long long q_xs_dma;
  unsigned long long q_ys_dma;
  unsigned long long q_zs_dma;
  unsigned long long p_inv_dma;
  unsigned long long prev_dma;
  unsigned long long p12t0_dma;
  unsigned long long p_dma;
  unsigned long long x0_dma;
  unsigned long long x1_dma;
  unsigned long long x2_dma;
  unsigned long long x3_dma;
  unsigned long long x4_dma;
  unsigned long long x5_dma;
  unsigned long long p12t1_dma;
  unsigned long long g_le_dma;
  unsigned long long w_le_dma;
  unsigned long long w_dma;
  unsigned long long k_dma;

  unsigned int  entlb;
  unsigned int  klen;
  unsigned char endian_mode;
  unsigned char rng_mode;
};

struct sm9_decapkey_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  unsigned long long     c_dma;
  struct sm9_point_dma   deb;
  unsigned long long     desc_dma;

  unsigned long long dsaa1_dma;
  unsigned long long t_xs_dma;
  unsigned long long t_ys_dma;
  unsigned long long t_zs_dma;
  unsigned long long one_dma;
  unsigned long long zero_dma;
  unsigned long long key_dma;
  unsigned long long p12r_dma;
  unsigned long long q_xs_dma;
  unsigned long long q_ys_dma;
  unsigned long long q_zs_dma;
  unsigned long long p_inv_dma;
  unsigned long long prev_dma;
  unsigned long long p12t0_dma;
  unsigned long long p_dma;
  unsigned long long x0_dma;
  unsigned long long x1_dma;
  unsigned long long x2_dma;
  unsigned long long x3_dma;
  unsigned long long x4_dma;
  unsigned long long x5_dma;
  unsigned long long p12t1_dma;
  unsigned long long w_le_dma;
  unsigned long long w_dma;

  unsigned long long hashin_dma;
  unsigned long long idb_dma;
  unsigned long long hashout_dma;
  unsigned long long k_dma;

  unsigned int  klen;
  unsigned int  entlb;
  unsigned char endian_mode;
};

struct sm9_enc_para {
  struct sm9_const_value    cv;
  struct sm9_ecc_dma        ed;
  unsigned long long        desc_dma;
  unsigned long long        hashin_dma;
  unsigned long long        one_dma;
  unsigned long long        idb_dma;
  unsigned long long        hid_dma;
  unsigned long long        hashout_dma;
  unsigned long long        ct_dma;
  struct sm9_point_dma      ppub_e;
  unsigned long long        r_dma;
  struct sm9_ciphertext_dma cd;

  unsigned long long dsaa1_dma;
  unsigned long long t_xs_dma;
  unsigned long long t_ys_dma;
  unsigned long long t_zs_dma;
  unsigned long long zero_dma;
  unsigned long long key_dma;
  unsigned long long p12r_dma;
  unsigned long long q_xs_dma;
  unsigned long long q_ys_dma;
  unsigned long long q_zs_dma;
  unsigned long long p_inv_dma;
  unsigned long long prev_dma;
  unsigned long long p12t0_dma;
  unsigned long long p_dma;
  unsigned long long x0_dma;
  unsigned long long x1_dma;
  unsigned long long x2_dma;
  unsigned long long x3_dma;
  unsigned long long x4_dma;
  unsigned long long x5_dma;
  unsigned long long p12t1_dma;
  unsigned long long g_le_dma;
  unsigned long long w_le_dma;
  unsigned long long w_dma;
  unsigned long long mes_dma;

  unsigned int  entlb;
  unsigned int  mlen;
  unsigned int  klen;
  unsigned char endian_mode;
  unsigned char rng_mode;
  unsigned char enc_type;
};

struct sm9_dec_para {
  struct sm9_const_value    cv;
  struct sm9_ecc_dma        ed;
  struct sm9_ciphertext_dma cd;
  struct sm9_point_dma      deb;
  unsigned long long        desc_dma;

  unsigned long long dsaa1_dma;
  unsigned long long t_xs_dma;
  unsigned long long t_ys_dma;
  unsigned long long t_zs_dma;
  unsigned long long one_dma;
  unsigned long long zero_dma;
  unsigned long long key_dma;
  unsigned long long p12r_dma;
  unsigned long long q_xs_dma;
  unsigned long long q_ys_dma;
  unsigned long long q_zs_dma;
  unsigned long long p_inv_dma;
  unsigned long long prev_dma;
  unsigned long long p12t0_dma;
  unsigned long long p_dma;
  unsigned long long x0_dma;
  unsigned long long x1_dma;
  unsigned long long x2_dma;
  unsigned long long x3_dma;
  unsigned long long x4_dma;
  unsigned long long x5_dma;
  unsigned long long p12t1_dma;
  unsigned long long w_le_dma;
  unsigned long long w_dma;

  unsigned long long hashin_dma;
  unsigned long long idb_dma;
  unsigned long long hashout_dma;
  unsigned long long ct_dma;
  unsigned long long mes_dma;

  unsigned int  mlen;
  unsigned int  klen;
  unsigned int  entlb;
  unsigned char endian_mode;
  unsigned char enc_type;
};

struct sm9_sig_para {
  struct sm9_const_value   cv;
  struct sm9_ecc_dma       ed;
  struct sm9_point_dma     ppub_s;
  struct sm9_signature_dma sd;
  struct sm9_point_dma     dsa;
  unsigned long long       desc_dma;

  unsigned long long dsaa1_dma;
  unsigned long long t_xs_dma;
  unsigned long long t_ys_dma;
  unsigned long long t_zs_dma;
  unsigned long long one_dma;
  unsigned long long zero_dma;
  unsigned long long key_dma;
  unsigned long long p12r_dma;
  unsigned long long q_xs_dma;
  unsigned long long q_ys_dma;
  unsigned long long q_zs_dma;
  unsigned long long p_inv_dma;
  unsigned long long prev_dma;
  unsigned long long p12t0_dma;
  unsigned long long p_dma;
  unsigned long long x0_dma;
  unsigned long long x1_dma;
  unsigned long long x2_dma;
  unsigned long long x3_dma;
  unsigned long long x4_dma;
  unsigned long long x5_dma;
  unsigned long long p12t1_dma;
  unsigned long long g_le_dma;
  unsigned long long w_le_dma;
  unsigned long long w_dma;
  unsigned long long r_dma;

  unsigned long long hashin_dma;
  unsigned long long two_dma;
  unsigned long long mes_dma;
  unsigned long long hashout_dma;

  unsigned int  mlen;
  unsigned char rng_mode;
  unsigned char endian_mode;
};

struct sm9_ver_para {
  struct sm9_const_value   cv;
  struct sm9_ecc_dma       ed;
  struct sm9_point_dma     ppub_s;
  struct sm9_signature_dma sd;
  unsigned long long       desc_dma;

  unsigned long long dsaa1_dma;
  unsigned long long t_xs_dma;
  unsigned long long t_ys_dma;
  unsigned long long t_zs_dma;
  unsigned long long one_dma;
  unsigned long long zero_dma;
  unsigned long long key_dma;
  unsigned long long p12r_dma;
  unsigned long long q_xs_dma;
  unsigned long long q_ys_dma;
  unsigned long long q_zs_dma;
  unsigned long long p_inv_dma;
  unsigned long long prev_dma;
  unsigned long long p12t0_dma;
  unsigned long long p_dma;
  unsigned long long x0_dma;
  unsigned long long x1_dma;
  unsigned long long x2_dma;
  unsigned long long x3_dma;
  unsigned long long x4_dma;
  unsigned long long x5_dma;
  unsigned long long p12t1_dma;
  unsigned long long g_le_dma;
  unsigned long long t_le_dma;
  unsigned long long w_le_dma;
  unsigned long long w_dma;

  unsigned long long hashin_dma;
  unsigned long long ida_dma;
  unsigned long long hid_dma;
  unsigned long long hashout_dma;
  unsigned long long two_dma;
  unsigned long long mes_dma;

  struct sm9_point_dma p;

  unsigned int  entla;
  unsigned int  mlen;
  unsigned char endian_mode;
};

struct sm9_exc_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  struct sm9_point_dma   ppub_e;
  struct sm9_point_dma   ra;
  struct sm9_point_dma   rb;
  struct sm9_point_dma   dea;
  struct sm9_point_dma   deb;
  unsigned long long     desc_dma;
  unsigned long long     k_dma;
  unsigned long long     r_dma;

  unsigned long long hashin_dma;
  unsigned long long one_dma;
  unsigned long long ida_dma;
  unsigned long long idb_dma;
  unsigned long long hid_dma;
  unsigned long long hashout_dma;

  unsigned long long dsaa1_dma;
  unsigned long long t_xs_dma;
  unsigned long long t_ys_dma;
  unsigned long long t_zs_dma;
  unsigned long long zero_dma;
  unsigned long long key_dma;
  unsigned long long p12r_dma;
  unsigned long long q_xs_dma;
  unsigned long long q_ys_dma;
  unsigned long long q_zs_dma;
  unsigned long long p_inv_dma;
  unsigned long long prev_dma;
  unsigned long long p12t0_dma;
  unsigned long long p_dma;
  unsigned long long x0_dma;
  unsigned long long x1_dma;
  unsigned long long x2_dma;
  unsigned long long x3_dma;
  unsigned long long x4_dma;
  unsigned long long x5_dma;
  unsigned long long p12t1_dma;
  unsigned long long g1b_le_dma;
  unsigned long long g3b_le_dma;
  unsigned long long g2b_le_dma;
  unsigned long long g1b_dma;
  unsigned long long g2b_dma;
  unsigned long long g3b_dma;
  unsigned long long g1a_le_dma;
  unsigned long long g2a_le_dma;
  unsigned long long g3a_le_dma;
  unsigned long long g1a_dma;
  unsigned long long g2a_dma;
  unsigned long long g3a_dma;

  unsigned long long ska_dma;
  unsigned long long skb_dma;
  unsigned long long msg_82_dma;
  unsigned long long msg_83_dma;
  unsigned long long sa_dma;
  unsigned long long sb_dma;
  unsigned long long s1_dma;
  unsigned long long s2_dma;

  unsigned int  entla;
  unsigned int  entlb;
  unsigned int  exklen;
  unsigned char endian_mode;
  unsigned char rng_mode;
};

struct sm9_excpre_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  struct sm9_point_dma   ppub_e;
  struct sm9_point_dma   r;
  unsigned long long     desc_dma;
  unsigned long long     r_dma;

  unsigned long long hashin_dma;
  unsigned long long one_dma;
  unsigned long long id_dma;
  unsigned long long hid_dma;
  unsigned long long hashout_dma;

  unsigned int  entl;
  unsigned char endian_mode;
  unsigned char rng_mode;
};

struct sm9_excmaina_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  struct sm9_point_dma   ppub_e;
  struct sm9_point_dma   ra;
  struct sm9_point_dma   rb;
  struct sm9_point_dma   dea;
  unsigned long long     desc_dma;
  unsigned long long     k_dma;

  unsigned long long hashin_dma;
  unsigned long long one_dma;
  unsigned long long ida_dma;
  unsigned long long idb_dma;
  unsigned long long hid_dma;
  unsigned long long hashout_dma;

  unsigned long long dsaa1_dma;
  unsigned long long t_xs_dma;
  unsigned long long t_ys_dma;
  unsigned long long t_zs_dma;
  unsigned long long zero_dma;
  unsigned long long key_dma;
  unsigned long long p12r_dma;
  unsigned long long q_xs_dma;
  unsigned long long q_ys_dma;
  unsigned long long q_zs_dma;
  unsigned long long p_inv_dma;
  unsigned long long prev_dma;
  unsigned long long p12t0_dma;
  unsigned long long p_dma;
  unsigned long long x0_dma;
  unsigned long long x1_dma;
  unsigned long long x2_dma;
  unsigned long long x3_dma;
  unsigned long long x4_dma;
  unsigned long long x5_dma;
  unsigned long long p12t1_dma;
  unsigned long long g1_le_dma;
  unsigned long long g3_le_dma;
  unsigned long long g2_le_dma;
  unsigned long long g1_dma;
  unsigned long long g2_dma;
  unsigned long long g3_dma;

  unsigned long long sk_dma;
  unsigned long long msg_82_dma;
  unsigned long long msg_83_dma;
  unsigned long long s1_dma;
  unsigned long long s2_dma;

  unsigned int  entla;
  unsigned int  entlb;
  unsigned int  exklen;
  unsigned char endian_mode;
};

struct sm9_excmainb_para {
  struct sm9_const_value cv;
  struct sm9_ecc_dma     ed;
  struct sm9_point_dma   ppub_e;
  struct sm9_point_dma   ra;
  struct sm9_point_dma   rb;
  struct sm9_point_dma   deb;
  unsigned long long     desc_dma;
  unsigned long long     r_dma;

  unsigned long long hashin_dma;
  unsigned long long one_dma;
  unsigned long long ida_dma;
  unsigned long long idb_dma;
  unsigned long long hid_dma;
  unsigned long long hashout_dma;

  unsigned long long dsaa1_dma;
  unsigned long long t_xs_dma;
  unsigned long long t_ys_dma;
  unsigned long long t_zs_dma;
  unsigned long long zero_dma;
  unsigned long long key_dma;
  unsigned long long p12r_dma;
  unsigned long long q_xs_dma;
  unsigned long long q_ys_dma;
  unsigned long long q_zs_dma;
  unsigned long long p_inv_dma;
  unsigned long long prev_dma;
  unsigned long long p12t0_dma;
  unsigned long long p_dma;
  unsigned long long x0_dma;
  unsigned long long x1_dma;
  unsigned long long x2_dma;
  unsigned long long x3_dma;
  unsigned long long x4_dma;
  unsigned long long x5_dma;
  unsigned long long p12t1_dma;
  unsigned long long g1_le_dma;
  unsigned long long g3_le_dma;
  unsigned long long g2_le_dma;
  unsigned long long g1_dma;
  unsigned long long g2_dma;
  unsigned long long g3_dma;

  unsigned long long sk_dma;
  unsigned long long msg_82_dma;
  unsigned long long msg_83_dma;
  unsigned long long s1_dma;
  unsigned long long s2_dma;

  unsigned int  entla;
  unsigned int  entlb;
  unsigned int  exklen;
  unsigned char endian_mode;
};

enum sm9_encrypt_mode { SM9_SM3= 0, SM9_SM4= 1 };

#endif
