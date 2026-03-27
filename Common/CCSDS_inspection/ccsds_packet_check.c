#include <stdio.h>
#include <inttypes.h>
#include "FreeRTOS.h"
#include "task.h"
/**
 * @file ccsds_packet_check.c
 * @brief CCSDS Packet Validation and Randomization Compliance Checker Implementation
 * 
 * Implements validation functions for CCSDS packet structures including
 * start-sequence validation, randomization/de-randomization, and 
 * transfer frame extraction from CLTU.
 * 
 * @author PWNLAB
 * @date 2026
 */

#include "ccsds_packet_check.h"

/* SPP primary header bit masks */
#define CCSDS_SPP_VERSION_MASK   0xE000
#define CCSDS_SPP_TYPE_MASK      0x1000
#define CCSDS_SPP_APID_MASK      0x07FF
#define CCSDS_SPP_SEQ_FLAGS_MASK 0xC000

typedef union {
    uint16_t whole;
    uint8_t data[2];
    struct {
        uint16_t scid: 10;
        uint16_t spare: 2;
        uint16_t ccf: 1;
        uint16_t bypass: 1;
        uint16_t ver: 2;
    } bits;
} cmd_transfer_frame_header0_type;

typedef union {
    uint16_t whole;
    uint8_t data[2];
    struct {
        uint16_t flength: 10;
        uint16_t vcid: 6;
    } bits;
} cmd_transfer_frame_header1_type;

#define ECB_BLOCK_SIZE 4U
#define ECB_HASH_TABLE_SIZE 256U

/*
 * Fixed-point log2 LUT: ccsds_log2_fp_lut[i] = round(log2(i) * 1024) for i=1..255
 * Q10 format (10 fractional bits, multiply = 1024 means 1.0)
 */
static const uint16_t ccsds_log2_fp_lut[256] = {
    0,     /* [0] unused */
    0,     /* log2(1)=0.000 */
    1024,  /* log2(2)=1.000 */
    1623,  /* log2(3)=1.585 */
    2048,  /* log2(4)=2.000 */
    2378,  /* log2(5)=2.322 */
    2647,  /* log2(6)=2.585 */
    2875,  /* log2(7)=2.807 */
    3072,  /* log2(8)=3.000 */
    3246,  /* log2(9)=3.170 */
    3402,  /* log2(10)=3.322 */
    3545,  /* log2(11)=3.459 */
    3671,  /* log2(12)=3.585 */
    3789,  /* log2(13)=3.700 */
    3899,  /* log2(14)=3.807 */
    4001,  /* log2(15)=3.907 */
    4096,  /* log2(16)=4.000 */
    4186,  /* log2(17)=4.087 */
    4270,  /* log2(18)=4.170 */
    4350,  /* log2(19)=4.248 */
    4426,  /* log2(20)=4.322 */
    4498,  /* log2(21)=4.392 */
    4569,  /* log2(22)=4.459 */
    4636,  /* log2(23)=4.524 */
    4695,  /* log2(24)=4.585 */
    4756,  /* log2(25)=4.644 */
    4813,  /* log2(26)=4.700 */
    4868,  /* log2(27)=4.755 */
    4923,  /* log2(28)=4.807 */
    4975,  /* log2(29)=4.858 */
    5025,  /* log2(30)=4.907 */
    5074,  /* log2(31)=4.954 */
    5120,  /* log2(32)=5.000 */
    5166,  /* log2(33)=5.044 */
    5210,  /* log2(34)=5.087 */
    5253,  /* log2(35)=5.129 */
    5294,  /* log2(36)=5.170 */
    5335,  /* log2(37)=5.209 */
    5374,  /* log2(38)=5.248 */
    5413,  /* log2(39)=5.285 */
    5450,  /* log2(40)=5.322 */
    5487,  /* log2(41)=5.358 */
    5523,  /* log2(42)=5.392 */
    5558,  /* log2(43)=5.426 */
    5593,  /* log2(44)=5.459 */
    5626,  /* log2(45)=5.492 */
    5660,  /* log2(46)=5.524 */
    5692,  /* log2(47)=5.554 */
    5724,  /* log2(48)=5.585 */
    5755,  /* log2(49)=5.615 */
    5786,  /* log2(50)=5.644 */
    5816,  /* log2(51)=5.672 */
    5846,  /* log2(52)=5.700 */
    5875,  /* log2(53)=5.728 */
    5903,  /* log2(54)=5.755 */
    5931,  /* log2(55)=5.781 */
    5959,  /* log2(56)=5.807 */
    5986,  /* log2(57)=5.833 */
    6013,  /* log2(58)=5.858 */
    6039,  /* log2(59)=5.883 */
    6065,  /* log2(60)=5.907 */
    6090,  /* log2(61)=5.931 */
    6115,  /* log2(62)=5.954 */
    6140,  /* log2(63)=5.977 */
    6144,  /* log2(64)=6.000 */
    6190,  /* log2(65)=6.022 */
    6214,  /* log2(66)=6.044 */
    6238,  /* log2(67)=6.066 */
    6262,  /* log2(68)=6.087 */
    6285,  /* log2(69)=6.109 */
    6308,  /* log2(70)=6.129 */
    6331,  /* log2(71)=6.150 */
    6354,  /* log2(72)=6.170 */
    6376,  /* log2(73)=6.190 */
    6398,  /* log2(74)=6.209 */
    6419,  /* log2(75)=6.229 */
    6441,  /* log2(76)=6.248 */
    6462,  /* log2(77)=6.267 */
    6483,  /* log2(78)=6.285 */
    6503,  /* log2(79)=6.304 */
    6524,  /* log2(80)=6.322 */
    6544,  /* log2(81)=6.340 */
    6564,  /* log2(82)=6.358 */
    6583,  /* log2(83)=6.375 */
    6603,  /* log2(84)=6.392 */
    6622,  /* log2(85)=6.409 */
    6641,  /* log2(86)=6.426 */
    6660,  /* log2(87)=6.443 */
    6678,  /* log2(88)=6.459 */
    6697,  /* log2(89)=6.476 */
    6715,  /* log2(90)=6.492 */
    6733,  /* log2(91)=6.508 */
    6750,  /* log2(92)=6.524 */
    6768,  /* log2(93)=6.539 */
    6785,  /* log2(94)=6.554 */
    6802,  /* log2(95)=6.570 */
    6819,  /* log2(96)=6.585 */
    6836,  /* log2(97)=6.600 */
    6852,  /* log2(98)=6.615 */
    6869,  /* log2(99)=6.629 */
    6885,  /* log2(100)=6.644 */
    6901,  /* log2(101)=6.658 */
    6917,  /* log2(102)=6.672 */
    6932,  /* log2(103)=6.686 */
    6948,  /* log2(104)=6.700 */
    6963,  /* log2(105)=6.714 */
    6978,  /* log2(106)=6.728 */
    6993,  /* log2(107)=6.741 */
    7008,  /* log2(108)=6.755 */
    7023,  /* log2(109)=6.768 */
    7037,  /* log2(110)=6.781 */
    7052,  /* log2(111)=6.794 */
    7066,  /* log2(112)=6.807 */
    7080,  /* log2(113)=6.820 */
    7094,  /* log2(114)=6.833 */
    7108,  /* log2(115)=6.845 */
    7122,  /* log2(116)=6.858 */
    7135,  /* log2(117)=6.870 */
    7149,  /* log2(118)=6.883 */
    7162,  /* log2(119)=6.895 */
    7175,  /* log2(120)=6.907 */
    7188,  /* log2(121)=6.919 */
    7201,  /* log2(122)=6.931 */
    7214,  /* log2(123)=6.943 */
    7227,  /* log2(124)=6.954 */
    7240,  /* log2(125)=6.966 */
    7252,  /* log2(126)=6.977 */
    7264,  /* log2(127)=6.989 */
    7168,  /* log2(128)=7.000 */
    7289,  /* log2(129)=7.011 */
    7301,  /* log2(130)=7.022 */
    7312,  /* log2(131)=7.033 */
    7324,  /* log2(132)=7.044 */
    7335,  /* log2(133)=7.055 */
    7347,  /* log2(134)=7.066 */
    7358,  /* log2(135)=7.076 */
    7369,  /* log2(136)=7.087 */
    7380,  /* log2(137)=7.098 */
    7391,  /* log2(138)=7.109 */
    7402,  /* log2(139)=7.119 */
    7413,  /* log2(140)=7.129 */
    7424,  /* log2(141)=7.140 */
    7434,  /* log2(142)=7.150 */
    7445,  /* log2(143)=7.160 */
    7456,  /* log2(144)=7.170 */
    7466,  /* log2(145)=7.180 */
    7476,  /* log2(146)=7.190 */
    7487,  /* log2(147)=7.200 */
    7497,  /* log2(148)=7.209 */
    7507,  /* log2(149)=7.219 */
    7517,  /* log2(150)=7.229 */
    7527,  /* log2(151)=7.238 */
    7537,  /* log2(152)=7.248 */
    7546,  /* log2(153)=7.257 */
    7556,  /* log2(154)=7.267 */
    7566,  /* log2(155)=7.276 */
    7575,  /* log2(156)=7.285 */
    7585,  /* log2(157)=7.294 */
    7594,  /* log2(158)=7.304 */
    7603,  /* log2(159)=7.313 */
    7612,  /* log2(160)=7.322 */
    7622,  /* log2(161)=7.331 */
    7631,  /* log2(162)=7.340 */
    7640,  /* log2(163)=7.349 */
    7649,  /* log2(164)=7.358 */
    7657,  /* log2(165)=7.366 */
    7666,  /* log2(166)=7.375 */
    7675,  /* log2(167)=7.384 */
    7683,  /* log2(168)=7.392 */
    7692,  /* log2(169)=7.401 */
    7700,  /* log2(170)=7.409 */
    7709,  /* log2(171)=7.418 */
    7717,  /* log2(172)=7.426 */
    7725,  /* log2(173)=7.434 */
    7734,  /* log2(174)=7.443 */
    7742,  /* log2(175)=7.451 */
    7750,  /* log2(176)=7.459 */
    7758,  /* log2(177)=7.467 */
    7766,  /* log2(178)=7.476 */
    7774,  /* log2(179)=7.484 */
    7782,  /* log2(180)=7.492 */
    7790,  /* log2(181)=7.500 */
    7798,  /* log2(182)=7.508 */
    7806,  /* log2(183)=7.516 */
    7813,  /* log2(184)=7.524 */
    7821,  /* log2(185)=7.531 */
    7829,  /* log2(186)=7.539 */
    7836,  /* log2(187)=7.547 */
    7844,  /* log2(188)=7.554 */
    7851,  /* log2(189)=7.562 */
    7858,  /* log2(190)=7.570 */
    7866,  /* log2(191)=7.577 */
    7873,  /* log2(192)=7.585 */
    7880,  /* log2(193)=7.592 */
    7887,  /* log2(194)=7.600 */
    7894,  /* log2(195)=7.607 */
    7902,  /* log2(196)=7.615 */
    7909,  /* log2(197)=7.622 */
    7916,  /* log2(198)=7.629 */
    7923,  /* log2(199)=7.636 */
    7930,  /* log2(200)=7.644 */
    7936,  /* log2(201)=7.651 */
    7943,  /* log2(202)=7.658 */
    7950,  /* log2(203)=7.665 */
    7957,  /* log2(204)=7.672 */
    7963,  /* log2(205)=7.679 */
    7970,  /* log2(206)=7.686 */
    7977,  /* log2(207)=7.693 */
    7983,  /* log2(208)=7.700 */
    7990,  /* log2(209)=7.707 */
    7996,  /* log2(210)=7.714 */
    8003,  /* log2(211)=7.721 */
    8009,  /* log2(212)=7.728 */
    8015,  /* log2(213)=7.734 */
    8022,  /* log2(214)=7.741 */
    8028,  /* log2(215)=7.748 */
    8034,  /* log2(216)=7.755 */
    8040,  /* log2(217)=7.761 */
    8047,  /* log2(218)=7.768 */
    8053,  /* log2(219)=7.775 */
    8059,  /* log2(220)=7.781 */
    8065,  /* log2(221)=7.788 */
    8071,  /* log2(222)=7.794 */
    8077,  /* log2(223)=7.801 */
    8083,  /* log2(224)=7.807 */
    8089,  /* log2(225)=7.814 */
    8095,  /* log2(226)=7.820 */
    8101,  /* log2(227)=7.826 */
    8107,  /* log2(228)=7.833 */
    8113,  /* log2(229)=7.839 */
    8118,  /* log2(230)=7.845 */
    8124,  /* log2(231)=7.852 */
    8130,  /* log2(232)=7.858 */
    8136,  /* log2(233)=7.864 */
    8141,  /* log2(234)=7.870 */
    8147,  /* log2(235)=7.876 */
    8153,  /* log2(236)=7.883 */
    8158,  /* log2(237)=7.889 */
    8164,  /* log2(238)=7.895 */
    8169,  /* log2(239)=7.901 */
    8175,  /* log2(240)=7.907 */
    8180,  /* log2(241)=7.912 */
    8186,  /* log2(242)=7.918 */
    8191,  /* log2(243)=7.924 */
    8197,  /* log2(244)=7.930 */
    8202,  /* log2(245)=7.936 */
    8207,  /* log2(246)=7.942 */
    8213,  /* log2(247)=7.948 */
    8218,  /* log2(248)=7.954 */
    8223,  /* log2(249)=7.959 */
    8228,  /* log2(250)=7.965 */
    8234,  /* log2(251)=7.971 */
    8239,  /* log2(252)=7.977 */
    8244,  /* log2(253)=7.982 */
    8249,  /* log2(254)=7.988 */
    8254   /* log2(255)=7.994 */
};

/* ===================================================================== */
/* Function Implementations                                             */
/* ===================================================================== */

/**
 * @brief Check CLTU (Command Link Transfer Unit) Start Sequence
 */
int32_t Check_Packet_CLTU(const uint8_t *data_cltu, uint16_t cltu_len)
{
    /* Validate input parameters */
    if (data_cltu == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (cltu_len < 2) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Check start sequence: 0xEB 0x90 */
    if (data_cltu[0] != CLTU_START_SEQ_0 || data_cltu[1] != CLTU_START_SEQ_1) {
        return CCSDS_CHECK_ERR_INVALID_CLTU_START;
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Check CADU (Channel Access Data Unit) Header (ASM)
 */
int32_t Check_Packet_CADU(const uint8_t *data_cadu, uint16_t cadu_len)
{
    uint32_t cadu_asm;

    /* Validate input parameters */
    if (data_cadu == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (cadu_len < 4) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Construct ASM from first 4 bytes (Big-Endian) */
    cadu_asm = (uint32_t)((data_cadu[0] << 24) | 
                          (data_cadu[1] << 16) | 
                          (data_cadu[2] << 8)  | 
                          data_cadu[3]);

    /* Check ASM value: 0x1ACFFC1D */
    if (cadu_asm != CADU_ASM) {
        return CCSDS_CHECK_ERR_INVALID_CADU_ASM;
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Apply CCSDS De-Randomization to data
 */
int32_t CCSDS_DeRandomize(uint8_t *data, uint16_t length)
{
    uint16_t i;

    /* Validate input parameters */
    if (data == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (length == 0) {
        return CCSDS_CHECK_OK;  /* No data to de-randomize */
    }

    /* Apply XOR with CCSDS randomization sequence */
    for (i = 0; i < length; i++) {
        data[i] ^= ccsds_randomization_sequence[i % CCSDS_RAND_SEQ_LEN];
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Apply CCSDS Randomization to data
 */
int32_t CCSDS_Randomize(uint8_t *data, uint16_t length)
{
    uint16_t i;

    /* Validate input parameters */
    if (data == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (length == 0) {
        return CCSDS_CHECK_OK;  /* No data to randomize */
    }

    /* Apply XOR with CCSDS randomization sequence */
    for (i = 0; i < length; i++) {
        data[i] ^= ccsds_randomization_sequence[i % CCSDS_RAND_SEQ_LEN];
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Check CCSDS Randomization in Transfer Frame
 */
int32_t Check_CCSDS_Randomization(const uint8_t *data_tframe, 
                                  uint16_t tframe_len, bool randomized)
{
    uint16_t i, idx;
    uint8_t test_byte;

    /* Validate input parameters */
    if (data_tframe == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (tframe_len == 0) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /*
     * Check randomization by verifying if the frame pattern matches
     * expected randomization characteristics. This is a validation check
     * to ensure the randomization algorithm was properly applied.
     */
    if (randomized) {
        /*
         * For randomized frames, we check that applying randomization
         * sequence produces varied output (not all zeros or same value)
         */
        uint16_t variation_count = 0;
        
        for (i = 0; i < tframe_len && i < 32; i++) {
            idx = i % CCSDS_RAND_SEQ_LEN;
            test_byte = data_tframe[i] ^ ccsds_randomization_sequence[idx];
            
            /* Count bytes that are different from randomization sequence */
            if (test_byte != ccsds_randomization_sequence[idx]) {
                variation_count++;
            }
        }
        
        /*
         * If after XOR with randomization sequence we still have variation,
         * it indicates proper randomization was applied
         */
        if (variation_count == 0) {
            return CCSDS_CHECK_ERR_INVALID_RANDOMIZATION;
        }
    } else {
        /*
         * For non-randomized frames, verify that the frame data doesn't
         * match the randomization sequence pattern
         */
        uint16_t match_count = 0;
        
        for (i = 0; i < tframe_len && i < 32; i++) {
            idx = i % CCSDS_RAND_SEQ_LEN;
            if (data_tframe[i] == ccsds_randomization_sequence[idx]) {
                match_count++;
            }
        }
        
        /* If too many matches, it might have been accidentally randomized */
        if (match_count > 28) {  /* Allow some coincidences */
            return CCSDS_CHECK_ERR_INVALID_RANDOMIZATION;
        }
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Extract Transfer Frame from CLTU and validate
 */
int32_t Extract_TF_From_CLTU(uint8_t *tframe_data, uint16_t *tframe_len,
                             uint16_t tframe_maxlen,
                             const uint8_t *cltu_data, uint16_t cltu_len,
                             bool apply_derand)
{
    uint16_t cltu_idx = 0;
    uint16_t tf_idx = 0;
    uint8_t code_block[CLTU_CODE_BLOCK_SIZE];
    bool tail_found = false;
    int32_t status;

    /* Validate input parameters */
    if (tframe_data == NULL || tframe_len == NULL || cltu_data == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (cltu_len < 10 || tframe_maxlen == 0) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Skip start sequence (caller should validate) */
    cltu_idx = 2;

    /* Extract code blocks until tail sequence is found */
    while (cltu_idx < cltu_len && !tail_found) {
        /* Check if we have enough data for a code block */
        /* Bounds check written to avoid -Wstrict-overflow under -Werror */
        if ((uint32_t)cltu_idx > (uint32_t)cltu_len ||
            ((uint32_t)cltu_len - (uint32_t)cltu_idx) < (uint32_t)CLTU_CODE_BLOCK_SIZE) {
            break;
        }

        /* Copy code block (7 bytes data + 1 byte ECC, we ignore ECC) */
        memcpy(code_block, &cltu_data[cltu_idx], CLTU_CODE_BLOCK_SIZE);

        /* Check for tail sequence (first 8 bytes of tail sequence) */
        if (code_block[0] == CLTU_TAIL_SEQ_0 &&
            code_block[1] == CLTU_TAIL_SEQ_1 &&
            code_block[2] == CLTU_TAIL_SEQ_2 &&
            code_block[3] == CLTU_TAIL_SEQ_3 &&
            code_block[4] == CLTU_TAIL_SEQ_4 &&
            code_block[5] == CLTU_TAIL_SEQ_5 &&
            code_block[6] == CLTU_TAIL_SEQ_6 &&
            code_block[7] == CLTU_TAIL_SEQ_7) {
            tail_found = true;
            break;
        }

        /* Copy 7 data bytes from code block (ignore parity/ECC byte) */
        if ((uint32_t)tf_idx > (uint32_t)tframe_maxlen ||
            ((uint32_t)tframe_maxlen - (uint32_t)tf_idx) < 7U) {
            return CCSDS_CHECK_ERR_INVALID_LENGTH;
        }

        memcpy(&tframe_data[tf_idx], code_block, 7);
        tf_idx += 7;
        cltu_idx += CLTU_CODE_BLOCK_SIZE;
    }

    /* Check if tail sequence was found */
    if (!tail_found) {
        return CCSDS_CHECK_ERR_INVALID_CLTU_TAIL;
    }

    /* Store extracted transfer frame length */
    *tframe_len = tf_idx;

    /* Apply de-randomization if requested */
    if (apply_derand && tf_idx > 0) {
        status = CCSDS_DeRandomize(tframe_data, tf_idx);
        if (status != CCSDS_CHECK_OK) {
            return status;
        }
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Extract Transfer Frame from CADU and validate
 */
int32_t Extract_TF_From_CADU(uint8_t *tframe_data, uint16_t *tframe_len,
                             uint16_t tframe_maxlen,
                             const uint8_t *cadu_data, uint16_t cadu_len,
                             bool apply_derand)
{
    int32_t status;
    uint16_t tf_len;

    /* Validate input parameters */
    if (tframe_data == NULL || tframe_len == NULL || cadu_data == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (cadu_len < 4 || tframe_maxlen == 0) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Copy Transfer Frame data (skip 4-byte ASM, caller should validate) */
    tf_len = (uint16_t)(cadu_len - 4);
    if (tf_len > tframe_maxlen) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    memcpy(tframe_data, &cadu_data[4], tf_len);
    *tframe_len = tf_len;

    /* Apply de-randomization if requested */
    if (apply_derand && tf_len > 0) {
        status = CCSDS_DeRandomize(tframe_data, tf_len);
        if (status != CCSDS_CHECK_OK) {
            return status;
        }
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Get error message for status code
 */
const char* CCSDS_GetErrorMessage(int32_t status)
{
    switch (status) {
        case CCSDS_CHECK_OK:
            return "Success";
        case CCSDS_CHECK_ERR_NULL_POINTER:
            return "Error: NULL pointer provided";
        case CCSDS_CHECK_ERR_INVALID_LENGTH:
            return "Error: Invalid packet length";
        case CCSDS_CHECK_ERR_INVALID_CLTU_START:
            return "Error: Invalid CLTU start sequence (expected 0xEB90)";
        case CCSDS_CHECK_ERR_INVALID_CLTU_TAIL:
            return "Error: Invalid CLTU tail sequence (0xC5C5C5C5C5C5C579)";
        case CCSDS_CHECK_ERR_INVALID_CADU_ASM:
            return "Error: Invalid CADU ASM (expected 0x1ACFFC1D)";
        case CCSDS_CHECK_ERR_INVALID_RANDOMIZATION:
            return "Error: CCSDS randomization check failed";
        case CCSDS_CHECK_ERR_TF_EXTRACTION_FAILED:
            return "Error: Transfer Frame extraction failed";
        case CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH:
            return "Error: Header length doesn't match actual payload size";
        case CCSDS_CHECK_ERR_REPLAY_ATTACK:
            return "Error: Possible replay attack detected (sequence number mismatch)";
        case CCSDS_CHECK_ERR_SEQUENCE_MISMATCH:
            return "Error: Sequence number gap too large (possible packet loss)";
        case CCSDS_CHECK_ERR_DECODING_FAILED:
            return "Error: Transfer Frame decoding failed";
        case CCSDS_CHECK_ERR_INVALID_TF_HEADER:
            return "Error: Invalid Transfer Frame header fields";
        case CCSDS_CHECK_ERR_INVALID_SPP_HEADER:
            return "Error: Invalid SPP header fields";
        case CCSDS_CHECK_WARN_PLAINTEXT_DETECTED:
            return "Warning: Plaintext payload detected (AS-5)";
        case CCSDS_CHECK_WARN_ECB_PATTERN_DETECTED:
            return "Warning: ECB block repetition detected (AS-4)";
        case CCSDS_CHECK_WARN_BRUTE_FORCE_DETECTED:
            return "Warning: CLTU start brute-force detected (AS-1)";
        case CCSDS_CHECK_WARN_RANDOMIZATION_BRUTE_FORCE:
            return "Warning: Randomization brute-force detected (AS-2)";
        case CCSDS_CHECK_WARN_REPLAY_SUSPICIOUS:
            return "Warning: Excessive replay indications detected (AS-6)";
        default:
            return "Error: Unknown status code";
    }
}

/**
 * @brief Print CLTU packet structure
 */
void Print_CLTU_Structure(const uint8_t *data_cltu, uint16_t cltu_len, FILE *fp)
{
    FILE *output = (fp == NULL) ? stdout : fp;
    uint16_t idx = 0;

    fprintf(output, "\n=== CLTU PACKET STRUCTURE ===\n");
    fprintf(output, "Total Length: %u bytes\n", cltu_len);

    if (cltu_len >= 2) {
        fprintf(output, "[0-1] Start Sequence: 0x%02X%02X", 
                data_cltu[0], data_cltu[1]);
        if (data_cltu[0] == CLTU_START_SEQ_0 && data_cltu[1] == CLTU_START_SEQ_1) {
            fprintf(output, " [VALID]\n");
        } else {
            fprintf(output, " [INVALID - Expected 0xEB90]\n");
        }
        idx = 2;
    }

    /* Print code blocks */
    int block_num = 0;
    while ((uint32_t)idx + (uint32_t)CLTU_CODE_BLOCK_SIZE <= (uint32_t)cltu_len) {
        fprintf(output, "[%u-%u] Code Block %d: ", 
                idx, idx + CLTU_CODE_BLOCK_SIZE - 1, block_num);
        
        /* Check for tail sequence */
        if (data_cltu[idx]     == CLTU_TAIL_SEQ_0 &&
            data_cltu[idx + 1] == CLTU_TAIL_SEQ_1 &&
            data_cltu[idx + 2] == CLTU_TAIL_SEQ_2 &&
            data_cltu[idx + 3] == CLTU_TAIL_SEQ_3 &&
            data_cltu[idx + 4] == CLTU_TAIL_SEQ_4 &&
            data_cltu[idx + 5] == CLTU_TAIL_SEQ_5 &&
            data_cltu[idx + 6] == CLTU_TAIL_SEQ_6 &&
            data_cltu[idx + 7] == CLTU_TAIL_SEQ_7) {
            fprintf(output, "TAIL SEQUENCE [VALID]\n");
            idx += CLTU_CODE_BLOCK_SIZE;
            break;
        }
        
        for (int i = 0; i < CLTU_CODE_BLOCK_SIZE; i++) {
            fprintf(output, "%02X", data_cltu[idx + i]);
            if (i == 6) fprintf(output, "|");  /* Separate data from ECC */
        }
        fprintf(output, "\n");
        
        idx += CLTU_CODE_BLOCK_SIZE;
        block_num++;
    }

    if (idx < cltu_len) {
        fprintf(output, "[%u-%u] Remaining bytes: ", idx, cltu_len - 1);
        while (idx < cltu_len) {
            fprintf(output, "%02X ", data_cltu[idx]);
            idx++;
        }
        fprintf(output, "\n");
    }

    fprintf(output, "==============================\n\n");
}

/**
 * @brief Print CADU packet structure
 */
void Print_CADU_Structure(const uint8_t *data_cadu, uint16_t cadu_len, FILE *fp)
{
    FILE *output = (fp == NULL) ? stdout : fp;
    uint32_t cadu_asm;

    fprintf(output, "\n=== CADU PACKET STRUCTURE ===\n");
    fprintf(output, "Total Length: %u bytes\n", cadu_len);

    if (cadu_len >= 4) {
        cadu_asm = (uint32_t)((data_cadu[0] << 24) | 
                              (data_cadu[1] << 16) | 
                              (data_cadu[2] << 8)  | 
                              data_cadu[3]);
        fprintf(output, "[0-3] ASM (Attached Sync Marker): 0x%08lX", (unsigned long)cadu_asm);
        if (cadu_asm == CADU_ASM) {
            fprintf(output, " [VALID]\n");
        } else {
            fprintf(output, " [INVALID - Expected 0x1ACFFC1D]\n");
        }
    }

    if (cadu_len > 4) {
        fprintf(output, "[4-%u] Transfer Frame Data (%u bytes):\n", 
                cadu_len - 1, cadu_len - 4);
        fprintf(output, "  First 32 bytes: ");
        for (uint16_t i = 4; i < cadu_len && i < 36; i++) {
            fprintf(output, "%02X ", data_cadu[i]);
            if ((i - 3) % 8 == 0) fprintf(output, "\n                ");
        }
        fprintf(output, "\n");
    }

    fprintf(output, "==============================\n\n");
}

/**
 * @brief Print hex dump of data
 */
void Print_Hex_Dump(const char *title, const uint8_t *data, 
                    uint16_t len, FILE *fp)
{
    FILE *output = (fp == NULL) ? stdout : fp;
    uint16_t i;

    if (title != NULL) {
        fprintf(output, "%s\n", title);
    }

    for (i = 0; i < len; i++) {
        fprintf(output, "%02X", data[i]);
        
        if ((i + 1) % 16 == 0) {
            fprintf(output, "\n");
        } else if ((i + 1) % 8 == 0) {
            fprintf(output, "  ");
        } else {
            fprintf(output, " ");
        }
    }

    if (len % 16 != 0) {
        fprintf(output, "\n");
    }
    fprintf(output, "\n");
}

/**
 * @brief Verify Transfer Frame Decoding with CCSDS Randomization
 */
int32_t Verify_TF_Decoding_With_Randomization(
    const uint8_t *cadu_data, uint16_t cadu_len,
    const uint8_t *expected_tf, uint16_t expected_tf_len,
    uint8_t *extracted_tf, uint16_t *extracted_tf_len)
{
    int32_t status;
    uint8_t temp_tf[320];
    uint16_t temp_len;

    /* Validate input parameters */
    if (cadu_data == NULL || expected_tf == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (cadu_len < 4) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Verify CADU ASM */
    status = Check_Packet_CADU(cadu_data, cadu_len);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Extract TF data (skip 4-byte ASM) */
    if ((uint32_t)cadu_len < (uint32_t)expected_tf_len + 4U) {
        return CCSDS_CHECK_ERR_DECODING_FAILED;
    }

    /* Copy TF from CADU (after ASM) */
    memcpy(temp_tf, &cadu_data[4], expected_tf_len);
    temp_len = expected_tf_len;

    /* De-randomize the extracted TF */
    status = CCSDS_DeRandomize(temp_tf, temp_len);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Compare extracted TF with expected TF */
    if (memcmp(temp_tf, expected_tf, expected_tf_len) != 0) {
        return CCSDS_CHECK_ERR_INVALID_RANDOMIZATION;
    }

    /* Store results if requested */
    if (extracted_tf != NULL) {
        memcpy(extracted_tf, temp_tf, temp_len);
    }
    if (extracted_tf_len != NULL) {
        *extracted_tf_len = temp_len;
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Parse TC Transfer Frame Header
 */
int32_t Parse_TC_TF_Header(const uint8_t *tf_data, uint16_t tf_len,
                           tc_tf_header_t *header)
{
    /* Validate input parameters */
    if (tf_data == NULL || header == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (tf_len < 2) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Parse SCID (10 bits): bytes 0-1, bits 0-9 */
    header->scid = ((tf_data[0] & 0x3F) << 4) | ((tf_data[1] & 0xF0) >> 4);

    /* Parse VCID (3 bits): byte 1, bits 1-3 */
    header->vcid = (tf_data[1] & 0x0E) >> 1;

    /* Parse Sequence Number: byte 2 (8 bits) */
    if (tf_len < 3) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }
    header->seq_num = tf_data[2];

    return CCSDS_CHECK_OK;
}

/**
 * @brief Parse TM Transfer Frame Header
 */
int32_t Parse_TM_TF_Header(const uint8_t *tf_data, uint16_t tf_len,
                           tm_tf_header_t *header)
{
    /* Validate input parameters */
    if (tf_data == NULL || header == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (tf_len < 4) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Parse SCID (10 bits): bytes 0-1, bits 0-9 */
    header->scid = ((tf_data[0] & 0x3F) << 4) | ((tf_data[1] & 0xF0) >> 4);

    /* Parse VCID (3 bits): byte 1, bits 1-3 */
    header->vcid = (tf_data[1] & 0x0E) >> 1;

    /* Parse MCFC (12 bits): bytes 2-3 */
    header->mcfc = ((tf_data[2] << 4) | ((tf_data[3] & 0xF0) >> 4)) & 0xFFF;

    return CCSDS_CHECK_OK;
}

/**
 * @brief Verify SPP Header Length
 */
int32_t Verify_SPP_Header_Length(const uint8_t *spp_packet, uint16_t packet_size,
                                 ccsds_spp_header_t *header)
{
    uint16_t declared_length;
    uint16_t actual_length;

    /* Validate input parameters */
    if (spp_packet == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (packet_size < 6) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Parse SPP header */
    if (header != NULL) {
        /* Stream ID: bytes 0-1 (Big-Endian) */
        header->stream_id = (spp_packet[0] << 8) | spp_packet[1];

        /* Sequence Count: bytes 2-3 (Big-Endian) */
        header->seq_count = (spp_packet[2] << 8) | spp_packet[3];

        /* Packet Length: bytes 4-5 (Big-Endian) - length is total - 1 */
        header->pkt_length = (spp_packet[4] << 8) | spp_packet[5];
    }

    /* Get declared length from header */
    declared_length = (spp_packet[4] << 8) | spp_packet[5];
    declared_length += 1;  /* Packet length field is actual_length - 1 */

    /* Get actual packet size */
    actual_length = packet_size;

    /* Compare lengths */
    if (declared_length != actual_length) {
        return CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH;
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Verify Transfer Frame Header Length
 */
int32_t Verify_TF_Header_Length(const uint8_t *tf_packet, uint16_t frame_size,
                                tc_tf_header_t *tc_header)
{
    int32_t status;
    tc_tf_header_t temp_header;

    /* Validate input parameters */
    if (tf_packet == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (frame_size < 6) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Parse TC Transfer Frame header */
    status = Parse_TC_TF_Header(tf_packet, frame_size, &temp_header);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Standard TC Transfer Frame size is typically 1024 bytes */
    /* For TM, typical size is 1279 bytes */
    /* We check if frame size is reasonable (between 256 and 2048 bytes) */
    if (frame_size < 256 || frame_size > 2048) {
        return CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH;
    }

    /* Store header if requested */
    if (tc_header != NULL) {
        *tc_header = temp_header;
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Verify TM Transfer Frame Header Length
 */
int32_t Verify_TM_TF_Header_Length(const uint8_t *tf_packet, uint16_t frame_size,
                                   tm_tf_header_t *tm_header)
{
    int32_t status;
    tm_tf_header_t temp_header;

    /* Validate input parameters */
    if (tf_packet == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (frame_size < 6) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Parse TM Transfer Frame header */
    status = Parse_TM_TF_Header(tf_packet, frame_size, &temp_header);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* We check if frame size is reasonable (between 256 and 2048 bytes) */
    if (frame_size < 256 || frame_size > 2048) {
        return CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH;
    }

    /* Store header if requested */
    if (tm_header != NULL) {
        *tm_header = temp_header;
    }

    return CCSDS_CHECK_OK;
}

int32_t Verify_TC_TF_Header_Fields(const tc_tf_header_t *header)
{
    if (header == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (header->scid > 0x3FF) {
        return CCSDS_CHECK_ERR_INVALID_TF_HEADER;
    }

    if (header->vcid > 0x07) {
        return CCSDS_CHECK_ERR_INVALID_TF_HEADER;
    }

    return CCSDS_CHECK_OK;
}

int32_t Verify_TM_TF_Header_Fields(const tm_tf_header_t *header)
{
    if (header == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (header->scid > 0x3FF) {
        return CCSDS_CHECK_ERR_INVALID_TF_HEADER;
    }

    if (header->vcid > 0x07) {
        return CCSDS_CHECK_ERR_INVALID_TF_HEADER;
    }

    if (header->mcfc > 0x0FFF) {
        return CCSDS_CHECK_ERR_INVALID_TF_HEADER;
    }

    return CCSDS_CHECK_OK;
}

int32_t Verify_SPP_Header_Fields(const ccsds_spp_header_t *header, bool expect_tc)
{
    uint16_t version;
    uint16_t type;
    uint16_t apid;

    if (header == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    version = (header->stream_id & CCSDS_SPP_VERSION_MASK) >> 13;
    type = (header->stream_id & CCSDS_SPP_TYPE_MASK) >> 12;
    apid = header->stream_id & CCSDS_SPP_APID_MASK;

    if (version != 0) {
        return CCSDS_CHECK_ERR_INVALID_SPP_HEADER;
    }

    if (expect_tc && type != 1) {
        return CCSDS_CHECK_ERR_INVALID_SPP_HEADER;
    }

    if (!expect_tc && type != 0) {
        return CCSDS_CHECK_ERR_INVALID_SPP_HEADER;
    }

    /* Reject idle APID (0x7FF) for integrity/security checks */
    if (apid == 0x7FF) {
        return CCSDS_CHECK_ERR_INVALID_SPP_HEADER;
    }

    /* Sequence flags are valid if within 2 bits; mask ensures range */
    (void)(header->seq_count & CCSDS_SPP_SEQ_FLAGS_MASK);

    return CCSDS_CHECK_OK;
}

/* ===================================================================== */
/* COP-1 FARM-1 Sliding Window (TC)                                     */
/* ===================================================================== */

#define COP1_FARM1_W_MIN 2U
#define COP1_FARM1_W_MAX 254U
/* W should be even in [2,254] for retransmission-allowed mode (PW=NW=W/2). */
#define COP1_FARM1_DEFAULT_W 200U

typedef struct {
    uint8_t vr;
    uint16_t w;
    uint16_t pw;
    uint16_t nw;
    bool initialized;
    bool vr_valid;
} cop1_farm1_state_t;

static uint16_t cop1_farm1_sanitize_w(uint16_t w)
{
    if (w < COP1_FARM1_W_MIN) {
        w = COP1_FARM1_W_MIN;
    } else if (w > COP1_FARM1_W_MAX) {
        w = COP1_FARM1_W_MAX;
    }

    if ((w & 1U) != 0U) {
        w--;
        if (w < COP1_FARM1_W_MIN) {
            w = COP1_FARM1_W_MIN;
        }
    }

    return w;
}

static void cop1_farm1_init(cop1_farm1_state_t *state, uint16_t w)
{
    if (state == NULL) {
        return;
    }

    w = cop1_farm1_sanitize_w(w);
    state->vr = 0U;
    state->w = w;
    state->pw = (uint16_t)(w / 2U);
    state->nw = (uint16_t)(w / 2U);
    state->initialized = true;
    state->vr_valid = false;
}

static int32_t cop1_farm1_on_ad(cop1_farm1_state_t *state, uint8_t ns)
{
    uint8_t forward_delta;
    uint8_t backward_delta;

    if (state == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (!state->initialized) {
        cop1_farm1_init(state, COP1_FARM1_DEFAULT_W);
    }

    if (!state->vr_valid) {
        state->vr = ns;
        state->vr_valid = true;
    }

    forward_delta = (uint8_t)(ns - state->vr);
    backward_delta = (uint8_t)(state->vr - ns);

    /* Type-AD events E1..E5 based on modulo-256 window comparisons. */
    if (forward_delta == 0U) {
        state->vr = (uint8_t)(state->vr + 1U);
        return CCSDS_CHECK_OK;
    }

    if ((state->pw > 0U) &&
        (forward_delta <= (uint8_t)(state->pw - 1U))) {
        return CCSDS_CHECK_ERR_SEQUENCE_MISMATCH;
    }

    if ((state->nw > 0U) &&
        (backward_delta != 0U) &&
        (backward_delta <= (uint8_t)state->nw)) {
        return CCSDS_CHECK_ERR_REPLAY_ATTACK;
    }

    return CCSDS_CHECK_ERR_SEQUENCE_MISMATCH;
}

/* ===================================================================== */
/* SPP Payload Security Analysis (AS-4, AS-5)                           */
/* ===================================================================== */

/**
 * @brief Calculate Shannon entropy of data (integer-only hot path)
 *
 * H(X) = log2(N) - (1/N) * sum(n_i * log2(n_i))
 * All arithmetic uses Q10 fixed-point via ccsds_log2_fp_lut[].
 * freq[] is static; only touched indices are cleared after use.
 */
float Calculate_Payload_Entropy(const uint8_t *data, uint16_t length)
{
    static uint16_t freq[256];
    uint8_t touched[256];
    uint16_t touched_count = 0U;
    uint32_t weighted_log2_sum_q10 = 0U;
    uint32_t log2_n_q10;
    int32_t entropy_q10;

    if (data == NULL || length == 0U) {
        return -1.0f;
    }

    /* Count byte frequencies, track which indices were used */
    for (uint16_t i = 0U; i < length; i++) {
        if (freq[data[i]] == 0U) {
            touched[touched_count] = data[i];
            touched_count++;
        }
        freq[data[i]]++;
    }

    /* sum(n_i * log2(n_i)) in Q10 — freq values are <= length <= 65535, fits in LUT */
    for (uint16_t t = 0U; t < touched_count; t++) {
        uint16_t n = freq[touched[t]];
        if (n <= 255U) {
            weighted_log2_sum_q10 += (uint32_t)n * (uint32_t)ccsds_log2_fp_lut[n];
        } else {
            /* For freq > 255: log2(n) = log2(n/2) + 1 = log2(n>>1) + 1024 (Q10) */
            uint16_t half = n >> 1U;
            uint32_t log2_val = (half <= 255U) ?
                (uint32_t)ccsds_log2_fp_lut[half] + 1024U :
                ((uint32_t)(31U - (uint32_t)__builtin_clz((uint32_t)half)) * 1024U);
            weighted_log2_sum_q10 += (uint32_t)n * log2_val;
        }
    }

    /* log2(N) in Q10 */
    if (length <= 255U) {
        log2_n_q10 = (uint32_t)ccsds_log2_fp_lut[length];
    } else {
        uint16_t half = length >> 1U;
        log2_n_q10 = (half <= 255U) ?
            (uint32_t)ccsds_log2_fp_lut[half] + 1024U :
            ((uint32_t)(31U - (uint32_t)__builtin_clz((uint32_t)half)) * 1024U);
    }

    /* H = log2(N) - (1/N) * sum => in Q10: log2_n_q10 - weighted_sum_q10 / N */
    entropy_q10 = (int32_t)log2_n_q10 - (int32_t)(weighted_log2_sum_q10 / (uint32_t)length);

    /* Clear only the touched freq entries */
    for (uint16_t t = 0U; t < touched_count; t++) {
        freq[touched[t]] = 0U;
    }

    return (float)entropy_q10 / 1024.0f;
}

/**
 * @brief Calculate printable ASCII ratio in data
 */
float Calculate_ASCII_Ratio(const uint8_t *data, uint16_t length)
{
    uint16_t printable_count = 0;
    
    if (data == NULL || length == 0) {
        return -1.0f;
    }
    
    /* Count printable ASCII characters (0x20-0x7E) */
    for (uint16_t i = 0; i < length; i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            printable_count++;
        }
    }
    
    return (float)printable_count / (float)length;
}

/**
 * @brief Detect repeated 4-byte blocks (ECB pattern)
 */
uint16_t Detect_ECB_Block_Repetition(const uint8_t *data, uint16_t length)
{
    uint16_t repeat_count = 0U;

    if (data == NULL || length < 8) {
        return 0;
    }

    for (uint16_t i = 0U; i < (uint16_t)(length - ECB_BLOCK_SIZE); i += ECB_BLOCK_SIZE) {
        for (uint16_t j = (uint16_t)(i + ECB_BLOCK_SIZE); j < (uint16_t)(length - ECB_BLOCK_SIZE); j += ECB_BLOCK_SIZE) {
            if (memcmp(&data[i], &data[j], ECB_BLOCK_SIZE) == 0) {
                repeat_count++;
            }
        }
    }

    return repeat_count;
}

/**
 * @brief Analyze SPP payload for ECB patterns (AS-4)
 */
int32_t Analyze_SPP_ECB_Pattern(const uint8_t *payload, uint16_t length,
                                spp_payload_analysis_t *result)
{
    if (payload == NULL || result == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (length == 0) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    result->ecb_repeats = Detect_ECB_Block_Repetition(payload, length);
    result->ecb_score = (float)result->ecb_repeats / (float)(length / 4U + 1U);

    if (result->ecb_repeats > 8U) {
        return CCSDS_CHECK_WARN_ECB_PATTERN_DETECTED;  /* AS-4 */
    }

    return CCSDS_CHECK_OK;
}

/**
 * @brief Analyze SPP payload for plaintext patterns (AS-5)
 */
int32_t Analyze_SPP_Plaintext(const uint8_t *payload, uint16_t length,
                              spp_payload_analysis_t *result)
{
    if (payload == NULL || result == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    if (length == 0) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    result->entropy = Calculate_Payload_Entropy(payload, length);
    result->ascii_ratio = Calculate_ASCII_Ratio(payload, length);
    result->plaintext_score = (result->ascii_ratio * 0.7f) +
                              ((8.0f - result->entropy) / 8.0f * 0.3f);

    if (result->plaintext_score > 0.6f) {
        return CCSDS_CHECK_WARN_PLAINTEXT_DETECTED;  /* AS-5 */
    }

    return CCSDS_CHECK_OK;
}

/* ===================================================================== */
/* Decoding Pipelines - High-level Functions                           */
/* ===================================================================== */



int32_t Decode_TC_CLTU_Pipeline(const uint8_t *cltu_data, uint16_t cltu_len,
                                 uint8_t *spp_out, uint16_t spp_max_len,
                                 uint16_t *spp_len, tc_tf_header_t *tf_header) {
    int32_t status;
    uint8_t tf_buffer[1024];
    uint16_t tf_len = 0;
    tc_tf_header_t header;
    ccsds_spp_header_t spp_header;
    static cop1_farm1_state_t tc_farm_state[8];

    if (cltu_data == NULL || spp_out == NULL || spp_len == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    /* Step 1: Validate CLTU start sequence */
    status = Check_Packet_CLTU(cltu_data, cltu_len);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 2: Extract Transfer Frame from CLTU (keep randomized) */
    status = Extract_TF_From_CLTU(tf_buffer, &tf_len, sizeof(tf_buffer),
                                   cltu_data, cltu_len, false);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 3: Check randomization on Transfer Frame */
    status = Check_CCSDS_Randomization(tf_buffer, tf_len, true);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 4: De-randomize Transfer Frame */
    status = CCSDS_DeRandomize(tf_buffer, tf_len);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 5: Verify Transfer Frame header length */
    status = Verify_TF_Header_Length(tf_buffer, tf_len, &header);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 6: Verify Transfer Frame header fields */
    status = Verify_TC_TF_Header_Fields(&header);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 7: FARM-1 sliding window check (per VCID) */
    if (header.vcid < 8) {
        status = cop1_farm1_on_ad(&tc_farm_state[header.vcid], header.seq_num);
        if (status != CCSDS_CHECK_OK) {
            return status;
        }
    }

    /* Step 8: Extract SPP packet from Transfer Frame */
    if (tf_len < 7) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Step 9: Validate SPP header length */
    status = Verify_SPP_Header_Length(&tf_buffer[6], tf_len - 6, &spp_header);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 10: Validate SPP header fields */
    status = Verify_SPP_Header_Fields(&spp_header, true);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 11: Copy SPP packet to output buffer */
    uint16_t spp_payload_len = tf_len - 6;  /* Skip 6-byte TF header */
    if (spp_payload_len > spp_max_len) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    memcpy(spp_out, &tf_buffer[6], spp_payload_len);
    *spp_len = spp_payload_len;

    /* Step 12: Analyze SPP payload security (AS-4, AS-5) */
    if (spp_payload_len > 6) {  /* Need at least SPP header */
        spp_payload_analysis_t analysis;
        int32_t plaintext_status = Analyze_SPP_Plaintext(
            &spp_out[6],  /* Skip SPP header */
            spp_payload_len - 6,
            &analysis
        );
        if (plaintext_status == CCSDS_CHECK_WARN_PLAINTEXT_DETECTED) {
            /* AS-5: Plaintext TC detected */
        }

        int32_t ecb_status = Analyze_SPP_ECB_Pattern(
            &spp_out[6],
            spp_payload_len - 6,
            &analysis
        );
        if (ecb_status == CCSDS_CHECK_WARN_ECB_PATTERN_DETECTED) {
            /* AS-4: ECB mode pattern detected */
        }
    }

    /* Return header if caller requested it */
    if (tf_header != NULL) {
        *tf_header = header;
    }

    return CCSDS_CHECK_OK;
}

int32_t Decode_TM_CADU_Pipeline(const uint8_t *cadu_data, uint16_t cadu_len,
                                 uint8_t *spp_out, uint16_t spp_max_len,
                                 uint16_t *spp_len, tm_tf_header_t *tf_header) {
    int32_t status;
    uint8_t tf_buffer[1024];
    uint16_t tf_len = 0;
    tm_tf_header_t header;
    ccsds_spp_header_t spp_header;

    if (cadu_data == NULL || spp_out == NULL || spp_len == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    /* Step 1: Validate CADU ASM */
    status = Check_Packet_CADU(cadu_data, cadu_len);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 2: Extract Transfer Frame from CADU (keep randomized) */
    status = Extract_TF_From_CADU(tf_buffer, &tf_len, sizeof(tf_buffer),
                                  cadu_data, cadu_len, false);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 3: Check randomization on Transfer Frame */
    status = Check_CCSDS_Randomization(tf_buffer, tf_len, true);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 4: De-randomize Transfer Frame */
    status = CCSDS_DeRandomize(tf_buffer, tf_len);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 5: Verify Transfer Frame header length */
    status = Verify_TM_TF_Header_Length(tf_buffer, tf_len, &header);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 6: Verify Transfer Frame header fields */
    status = Verify_TM_TF_Header_Fields(&header);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 7: TM sequence check removed (COP-1 FARM-1 applies to TC only) */

    /* Step 8: Extract SPP packet from Transfer Frame */
    if (tf_len < 6) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    /* Step 9: Validate SPP header length */
    status = Verify_SPP_Header_Length(&tf_buffer[6], tf_len - 6, &spp_header);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 10: Validate SPP header fields */
    status = Verify_SPP_Header_Fields(&spp_header, false);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    /* Step 11: Copy SPP packet to output buffer */
    uint16_t spp_payload_len = tf_len - 6;  /* Skip 6-byte TF header */
    if (spp_payload_len > spp_max_len) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    memcpy(spp_out, &tf_buffer[6], spp_payload_len);
    *spp_len = spp_payload_len;

    /* Step 12: Analyze SPP payload security (AS-4, AS-5) */
    if (spp_payload_len > 6) {  /* Need at least SPP header */
        spp_payload_analysis_t analysis;
        int32_t plaintext_status = Analyze_SPP_Plaintext(
            &spp_out[6],  /* Skip SPP header */
            spp_payload_len - 6,
            &analysis
        );
        if (plaintext_status == CCSDS_CHECK_WARN_PLAINTEXT_DETECTED) {
            /* AS-5: Plaintext TM detected */
        }

        int32_t ecb_status = Analyze_SPP_ECB_Pattern(
            &spp_out[6],
            spp_payload_len - 6,
            &analysis
        );
        if (ecb_status == CCSDS_CHECK_WARN_ECB_PATTERN_DETECTED) {
            /* AS-4: ECB mode pattern detected */
        }
    }

    /* Return header if caller requested it */
    if (tf_header != NULL) {
        *tf_header = header;
    }

    return CCSDS_CHECK_OK;
}


/* ===================================================================== */
/* Standalone demo (optional)                                            */
/* ===================================================================== */

/*
 * You asked to hardcode demo packets as global variables and run the checker
 * directly from this .c file.
 *
 * Build (standalone executable):
 *   gcc -std=c11 -O2 -Wall -Wextra -DCCSDS_PACKET_CHECK_STANDALONE \
 *       ccsds_packet_check.c -o ccsds_packet_check_demo
 *
 * Run:
 *   ./ccsds_packet_check_demo          # run both demo packets
 *   ./ccsds_packet_check_demo cltu     # only CLTU
 *   ./ccsds_packet_check_demo cadu     # only CADU
 */

#define CCSDS_DEMO_TC_COUNT 10U
#define CCSDS_DEMO_TC_CLTU_MAX_LEN 186U
#define CCSDS_DEMO_TC_TF_MAX_LEN 153U
#define CCSDS_DEMO_TC_SPP_MAX_LEN 146U

#if defined(__GNUC__)
__attribute__((unused))
#endif
static const uint8_t g_demo_tc_cltu_0[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0xD0, 0x9A, 0x15, 0xB8, 0x5E, 0x7C, 0x8E, 0x2C, 0x92, 0xA1, 0xA7,
    0x79, 0xC8, 0xBE, 0xF8, 0xD1, 0xAA, 0xAA, 0xAA, 0xAA, 0xF0, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5,
    0xC5, 0x79
};

static const uint8_t g_demo_tc_cltu_1[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0x58, 0x9A, 0x15, 0xC3, 0x8A, 0x7C, 0x8E, 0x2C, 0x1A, 0xAF, 0xA7,
    0xB7, 0x2C, 0x47, 0xCE, 0x5B, 0xA7, 0x53, 0xFE, 0x03, 0xE6, 0x8D, 0xDB, 0x5F, 0x7E, 0x71, 0xDE,
    0x88, 0x52, 0x94, 0xCD, 0xEA, 0xB1, 0xFE, 0x90, 0x1D, 0xA4, 0x81, 0x34, 0x1A, 0xE1, 0x79, 0x1C,
    0x59, 0xBC, 0x27, 0x5B, 0x4F, 0x6E, 0x8D, 0x9C, 0xB5, 0x4C, 0x2E, 0xFB, 0x98, 0x65, 0x45, 0x7E,
    0x7C, 0x40, 0x14, 0x21, 0xE3, 0x11, 0x29, 0x9B, 0xD5, 0x64, 0x63, 0xFD, 0x20, 0x3B, 0x02, 0x68,
    0x35, 0xAA, 0xC2, 0xF2, 0x38, 0xB2, 0x4E, 0xB6, 0x9E, 0xD8, 0xDD, 0x1B, 0x39, 0x6A, 0x5D, 0xF7,
    0x30, 0xC8, 0xCA, 0xA5, 0x88, 0x95, 0x58, 0x6C, 0xA2, 0xBA, 0x43, 0x27, 0x56, 0xAA, 0xC7, 0xFA,
    0x40, 0x9A, 0x76, 0x04, 0xD0, 0x6B, 0x85, 0xE4, 0x71, 0xB2, 0x64, 0x9D, 0x6D, 0x3D, 0xBA, 0x36,
    0x72, 0x28, 0xD4, 0xBB, 0xEE, 0x61, 0x95, 0x15, 0xF9, 0xC4, 0xF0, 0x50, 0x87, 0x8C, 0x44, 0xA6,
    0x6F, 0x72, 0x55, 0x8F, 0xF4, 0x80, 0xEC, 0x09, 0xA0, 0x86, 0xD7, 0x0B, 0xC8, 0xE2, 0xC9, 0x3A,
    0xDA, 0xC0, 0x7B, 0x74, 0x6C, 0xE5, 0xA9, 0x77, 0xDC, 0x38, 0xC3, 0x2A, 0x3C, 0xB3, 0x62, 0x43,
    0xAA, 0x7C, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0x79
};

static const uint8_t g_demo_tc_cltu_2[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0xF6, 0x9A, 0x15, 0x76, 0xB6, 0x7C, 0x8E, 0x2C, 0xB4, 0xB8, 0xA7,
    0xD3, 0xC8, 0x23, 0xA8, 0x3B, 0xE2, 0x11, 0xB8, 0x32, 0x8A, 0xA2, 0xBF, 0x3E, 0x0A, 0x10, 0xF1,
    0x88, 0x88, 0x94, 0xCD, 0xEA, 0xB1, 0xFE, 0x90, 0x1D, 0xA4, 0x81, 0x34, 0x1A, 0xE1, 0x79, 0x1C,
    0x59, 0xBC, 0x27, 0x5B, 0x4F, 0x6E, 0x8D, 0x9C, 0xB5, 0x4C, 0x2E, 0xFB, 0xA5, 0x7A, 0xF1, 0x6D,
    0xAA, 0xEC, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0x79
};

static const uint8_t g_demo_tc_cltu_3[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0xA4, 0x9A, 0x15, 0x76, 0x6C, 0x7C, 0x8E, 0x2C, 0xC6, 0xAA, 0xA7,
    0xD3, 0x86, 0x23, 0xA8, 0x3B, 0xE2, 0x11, 0xB8, 0x32, 0x8A, 0xA2, 0xBF, 0x3E, 0x0A, 0x10, 0xF1,
    0x88, 0x88, 0x94, 0xCD, 0xEA, 0xB1, 0xFE, 0xF4, 0x78, 0x42, 0xE7, 0x55, 0x6F, 0x8D, 0x0D, 0x1C,
    0x59, 0x86, 0x27, 0x5B, 0x4F, 0x6E, 0x8D, 0x9C, 0xB5, 0x4C, 0x2E, 0xFB, 0x98, 0x65, 0x45, 0x7E,
    0x7C, 0x40, 0x14, 0x21, 0xE3, 0x11, 0x29, 0x9B, 0xD5, 0x64, 0x63, 0xFD, 0x20, 0x3B, 0x02, 0x68,
    0x35, 0xAA, 0xC2, 0xF2, 0x38, 0xB2, 0x4E, 0xB6, 0x9E, 0xD8, 0xDD, 0x1B, 0x39, 0x6A, 0x5D, 0xF7,
    0x30, 0xC8, 0xCA, 0x8A, 0xFC, 0xF8, 0x28, 0x43, 0xC6, 0x56, 0x22, 0x53, 0x37, 0xAA, 0xC7, 0xFA,
    0x4C, 0x18, 0xF5, 0x9B, 0x3B, 0xAA, 0xAA, 0xAA, 0xAA, 0x04, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5,
    0xC5, 0x79
};

static const uint8_t g_demo_tc_cltu_4[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0xD0, 0x9A, 0x15, 0xF8, 0xCC, 0x7C, 0x8E, 0x2C, 0x92, 0xAD, 0xA7,
    0xE1, 0x0A, 0x3F, 0xF8, 0xD1, 0xAA, 0xAA, 0xAA, 0xAA, 0xEE, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5,
    0xC5, 0x79
};

static const uint8_t g_demo_tc_cltu_5[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0x98, 0x9A, 0x15, 0xF8, 0x5A, 0x7C, 0x8E, 0x2C, 0xDA, 0xAF, 0xA7,
    0xF6, 0xDC, 0x46, 0xCE, 0x5A, 0x97, 0x7D, 0xCC, 0x32, 0x9E, 0xC6, 0xDA, 0x58, 0x6B, 0x65, 0x9D,
    0xFC, 0xA4, 0x94, 0xCD, 0xEA, 0xB1, 0xFE, 0x90, 0x1D, 0xA4, 0x81, 0x34, 0x1A, 0xE1, 0x79, 0x1C,
    0x59, 0xBC, 0x27, 0x5B, 0x4F, 0x6E, 0x8D, 0x9C, 0xB5, 0x4C, 0x2E, 0xFB, 0x98, 0x65, 0x45, 0x7E,
    0x7C, 0x40, 0x14, 0x21, 0xE3, 0x11, 0x29, 0x9B, 0xD5, 0x64, 0x63, 0xFD, 0x20, 0x3B, 0x02, 0x68,
    0x35, 0xAA, 0xC2, 0xF2, 0x38, 0xB2, 0x4E, 0xB6, 0x9E, 0xD8, 0xDD, 0x1B, 0x39, 0x6A, 0x5D, 0xF7,
    0x30, 0xC8, 0xCA, 0x99, 0x2D, 0x07, 0x71, 0xAA, 0xAA, 0xB2, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5,
    0xC5, 0x79
};

static const uint8_t g_demo_tc_cltu_6[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0x9C, 0x9A, 0x15, 0xF8, 0xF8, 0x7C, 0x8E, 0x2C, 0xDE, 0xAE, 0xA7,
    0xB7, 0x34, 0x07, 0xCE, 0x5A, 0x97, 0x7D, 0xCC, 0x32, 0x26, 0xA2, 0xBF, 0x3E, 0x0A, 0x74, 0x94,
    0xEE, 0x26, 0xF5, 0xB8, 0x86, 0xC5, 0xFE, 0x90, 0x1D, 0xDA, 0x81, 0x34, 0x1A, 0xE1, 0x79, 0x1C,
    0x59, 0xBC, 0x27, 0x5B, 0x4F, 0x6E, 0x8D, 0x9C, 0xB5, 0x4C, 0x2E, 0xFB, 0x98, 0x65, 0x45, 0x7E,
    0x7C, 0x40, 0x14, 0x21, 0xE3, 0x11, 0x29, 0x9B, 0xD5, 0x64, 0x63, 0xFD, 0x20, 0x3B, 0x02, 0x68,
    0x35, 0xAA, 0xC2, 0xF2, 0x38, 0xB2, 0x4E, 0xB6, 0x9E, 0xD8, 0xDD, 0x1B, 0x39, 0x6A, 0x5D, 0xF7,
    0x30, 0xC8, 0xCA, 0x8A, 0xFC, 0xF8, 0x28, 0x50, 0xE7, 0x1A, 0xF0, 0x32, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0x60, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0x79
};

static const uint8_t g_demo_tc_cltu_7[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0xA0, 0x9A, 0x15, 0xF8, 0xAE, 0x7C, 0x8E, 0x2C, 0xC2, 0xA5, 0xA7,
    0xB7, 0xB6, 0x46, 0xCE, 0x5A, 0x97, 0x7D, 0xCC, 0x32, 0x9E, 0xA2, 0xBF, 0x3E, 0x0A, 0x10, 0xF1,
    0x88, 0x88, 0x94, 0xA9, 0x8F, 0xD7, 0x9F, 0xE5, 0x71, 0xE8, 0xF5, 0x34, 0x1A, 0xE1, 0x79, 0x1C,
    0x59, 0x2C, 0x27, 0x5B, 0x4F, 0x6E, 0x8D, 0x9C, 0xB5, 0x4C, 0x2E, 0xFB, 0x98, 0x65, 0x45, 0x7E,
    0x7C, 0x40, 0x14, 0x21, 0xE3, 0x11, 0x29, 0x9B, 0xD5, 0x64, 0x63, 0xFD, 0x20, 0x3B, 0x02, 0x68,
    0x35, 0xAA, 0xC2, 0xF2, 0x38, 0xB2, 0x4E, 0xB6, 0x9E, 0xD8, 0xDD, 0x1B, 0x39, 0x6A, 0x5D, 0xF7,
    0x30, 0xC8, 0xCA, 0x8A, 0xFC, 0xF8, 0x28, 0x43, 0xC6, 0x56, 0x22, 0x53, 0x4B, 0x63, 0x9B, 0xD0,
    0xAA, 0xC2, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0x79
};

static const uint8_t g_demo_tc_cltu_8[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0xD2, 0x9A, 0x15, 0xF0, 0xBE, 0x7C, 0x8E, 0x2C, 0x90, 0xBC, 0xA7,
    0xB7, 0x2C, 0x46, 0x85, 0x92, 0xEE, 0x6F, 0xAA, 0xAA, 0x66, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5,
    0xC5, 0x79
};

static const uint8_t g_demo_tc_cltu_9[] = {
    0xEB, 0x90, 0xDF, 0x49, 0x06, 0xD0, 0x9A, 0x15, 0xF0, 0x2A, 0x7C, 0x8E, 0x2C, 0x92, 0xA1, 0xA7,
    0x37, 0x94, 0xFF, 0xF8, 0xD1, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5,
    0xC5, 0x79
};

static const uint8_t *const g_demo_tc_cltu[CCSDS_DEMO_TC_COUNT] = {
    g_demo_tc_cltu_0,
    g_demo_tc_cltu_1,
    g_demo_tc_cltu_2,
    g_demo_tc_cltu_3,
    g_demo_tc_cltu_4,
    g_demo_tc_cltu_5,
    g_demo_tc_cltu_6,
    g_demo_tc_cltu_7,
    g_demo_tc_cltu_8,
    g_demo_tc_cltu_9
};

static const uint16_t g_demo_tc_cltu_len[CCSDS_DEMO_TC_COUNT] = {
    (uint16_t)sizeof(g_demo_tc_cltu_0), (uint16_t)sizeof(g_demo_tc_cltu_1), (uint16_t)sizeof(g_demo_tc_cltu_2), (uint16_t)sizeof(g_demo_tc_cltu_3), (uint16_t)sizeof(g_demo_tc_cltu_4), (uint16_t)sizeof(g_demo_tc_cltu_5), (uint16_t)sizeof(g_demo_tc_cltu_6), (uint16_t)sizeof(g_demo_tc_cltu_7), (uint16_t)sizeof(g_demo_tc_cltu_8), (uint16_t)sizeof(g_demo_tc_cltu_9)
};

static const uint8_t g_demo_tc_tf_0[] = {
    0x20, 0x01, 0x08, 0x10, 0x00, 0x18, 0xC8, 0xC0, 0x00, 0x00, 0x01, 0x0C, 0x00, 0xCE, 0xF8, 0x36,
    0x8B
};

static const uint8_t g_demo_tc_tf_1[] = {
    0x20, 0x01, 0x08, 0x98, 0x00, 0x18, 0xB3, 0xC0, 0x00, 0x00, 0x89, 0x02, 0x00, 0x00, 0x01, 0x00,
    0x01, 0x30, 0x2E, 0x32, 0x31, 0x2F, 0x64, 0x61, 0x74, 0x61, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x2F, 0x74, 0x6D, 0x70, 0x2F, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x40, 0x82, 0xE2
};

static const uint8_t g_demo_tc_tf_2[] = {
    0x20, 0x01, 0x08, 0x36, 0x00, 0x18, 0x06, 0xC0, 0x00, 0x00, 0x27, 0x15, 0x00, 0x64, 0x65, 0x66,
    0x61, 0x75, 0x6C, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3D, 0x1F, 0xB4, 0x13
};

static const uint8_t g_demo_tc_tf_3[] = {
    0x20, 0x01, 0x08, 0x64, 0x00, 0x18, 0x06, 0xC0, 0x00, 0x00, 0x55, 0x07, 0x00, 0x64, 0x65, 0x66,
    0x61, 0x75, 0x6C, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0C, 0x83, 0x9F, 0xEB
};

static const uint8_t g_demo_tc_tf_4[] = {
    0x20, 0x01, 0x08, 0x10, 0x00, 0x18, 0x88, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x56, 0x79, 0x36,
    0x8B
};

static const uint8_t g_demo_tc_tf_5[] = {
    0x20, 0x01, 0x08, 0x58, 0x00, 0x18, 0x88, 0xC0, 0x00, 0x00, 0x49, 0x02, 0x00, 0x41, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0xD1, 0xFF, 0x59
};

static const uint8_t g_demo_tc_tf_6[] = {
    0x20, 0x01, 0x08, 0x5C, 0x00, 0x18, 0x88, 0xC0, 0x00, 0x00, 0x4D, 0x03, 0x00, 0x00, 0x41, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x21, 0xD2, 0x61
};

static const uint8_t g_demo_tc_tf_7[] = {
    0x20, 0x01, 0x08, 0x60, 0x00, 0x18, 0x88, 0xC0, 0x00, 0x00, 0x51, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66,
    0x61, 0x75, 0x6C, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC9, 0x5C,
    0x2A
};

static const uint8_t g_demo_tc_tf_8[] = {
    0x20, 0x01, 0x08, 0x12, 0x00, 0x18, 0x80, 0xC0, 0x00, 0x00, 0x03, 0x11, 0x00, 0x00, 0x00, 0x4B,
    0xC8, 0x79, 0x12
};

static const uint8_t g_demo_tc_tf_9[] = {
    0x20, 0x01, 0x08, 0x10, 0x00, 0x18, 0x80, 0xC0, 0x00, 0x00, 0x01, 0x0C, 0x00, 0x80, 0xB9, 0x36,
    0x8B
};

static const uint8_t *const g_demo_tc_tf[CCSDS_DEMO_TC_COUNT] = {
    g_demo_tc_tf_0,
    g_demo_tc_tf_1,
    g_demo_tc_tf_2,
    g_demo_tc_tf_3,
    g_demo_tc_tf_4,
    g_demo_tc_tf_5,
    g_demo_tc_tf_6,
    g_demo_tc_tf_7,
    g_demo_tc_tf_8,
    g_demo_tc_tf_9
};

static const uint16_t g_demo_tc_tf_len[CCSDS_DEMO_TC_COUNT] = {
    (uint16_t)sizeof(g_demo_tc_tf_0), (uint16_t)sizeof(g_demo_tc_tf_1), (uint16_t)sizeof(g_demo_tc_tf_2), (uint16_t)sizeof(g_demo_tc_tf_3), (uint16_t)sizeof(g_demo_tc_tf_4), (uint16_t)sizeof(g_demo_tc_tf_5), (uint16_t)sizeof(g_demo_tc_tf_6), (uint16_t)sizeof(g_demo_tc_tf_7), (uint16_t)sizeof(g_demo_tc_tf_8), (uint16_t)sizeof(g_demo_tc_tf_9)
};

static const uint8_t g_demo_tc_spp_0[] = {
    0x18, 0xC8, 0xC0, 0x00, 0x00, 0x01, 0x0C, 0x00, 0xCE, 0xF8
};

static const uint8_t g_demo_tc_spp_1[] = {
    0x18, 0xB3, 0xC0, 0x00, 0x00, 0x89, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x30, 0x2E, 0x32, 0x31,
    0x2F, 0x64, 0x61, 0x74, 0x61, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2F, 0x74, 0x6D, 0x70, 0x2F, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x17, 0x40
};

static const uint8_t g_demo_tc_spp_2[] = {
    0x18, 0x06, 0xC0, 0x00, 0x00, 0x27, 0x15, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3D, 0x1F
};

static const uint8_t g_demo_tc_spp_3[] = {
    0x18, 0x06, 0xC0, 0x00, 0x00, 0x55, 0x07, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61,
    0x75, 0x6C, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x83
};

static const uint8_t g_demo_tc_spp_4[] = {
    0x18, 0x88, 0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x56, 0x79
};

static const uint8_t g_demo_tc_spp_5[] = {
    0x18, 0x88, 0xC0, 0x00, 0x00, 0x49, 0x02, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x13, 0xD1
};

static const uint8_t g_demo_tc_spp_6[] = {
    0x18, 0x88, 0xC0, 0x00, 0x00, 0x4D, 0x03, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x13, 0x21
};

static const uint8_t g_demo_tc_spp_7[] = {
    0x18, 0x88, 0xC0, 0x00, 0x00, 0x51, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC9
};

static const uint8_t g_demo_tc_spp_8[] = {
    0x18, 0x80, 0xC0, 0x00, 0x00, 0x03, 0x11, 0x00, 0x00, 0x00, 0x4B, 0xC8
};

static const uint8_t g_demo_tc_spp_9[] = {
    0x18, 0x80, 0xC0, 0x00, 0x00, 0x01, 0x0C, 0x00, 0x80, 0xB9
};

static const uint8_t *const g_demo_tc_spp[CCSDS_DEMO_TC_COUNT] = {
    g_demo_tc_spp_0,
    g_demo_tc_spp_1,
    g_demo_tc_spp_2,
    g_demo_tc_spp_3,
    g_demo_tc_spp_4,
    g_demo_tc_spp_5,
    g_demo_tc_spp_6,
    g_demo_tc_spp_7,
    g_demo_tc_spp_8,
    g_demo_tc_spp_9
};

static const uint16_t g_demo_tc_spp_len[CCSDS_DEMO_TC_COUNT] = {
    (uint16_t)sizeof(g_demo_tc_spp_0), (uint16_t)sizeof(g_demo_tc_spp_1), (uint16_t)sizeof(g_demo_tc_spp_2), (uint16_t)sizeof(g_demo_tc_spp_3), (uint16_t)sizeof(g_demo_tc_spp_4), (uint16_t)sizeof(g_demo_tc_spp_5), (uint16_t)sizeof(g_demo_tc_spp_6), (uint16_t)sizeof(g_demo_tc_spp_7), (uint16_t)sizeof(g_demo_tc_spp_8), (uint16_t)sizeof(g_demo_tc_spp_9)
};


static const uint8_t g_demo_tm_cadu[30] = {
    0x1A, 0xCF, 0xFC, 0x1D, 0xEB, 0x90, 0xDF, 0x42, 0x1C, 0xF0, 0x9A, 0x0D, 0x78, 0xBB, 0xBE, 0x8E,
    0x2E, 0x93, 0xAA, 0x79, 0x1A, 0xBB, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0x79
};

#include <stdio.h>
#include <inttypes.h>
#include <string.h>

/**
 * @brief Main entry point for CCSDS packet check
 * 
 * This function can be called either from the ccsds_inspection shell command
 * or from a standalone main() function.
 * It uses global variables that should be set up by the application.
 */

#define CCSDS_DEMO_WINDOW_TICKS 5000U
#define CCSDS_AS_RUN_SECONDS    1000U
#define CCSDS_RUN_ITERATIONS_DEFAULT 100000U
#define CCSDS_RUN_DELAY_DEFAULT_MS 1U
#ifndef pdMS_TO_TICKS
#define pdMS_TO_TICKS(x) (x)
#endif

static uint32_t g_ccsds_run_iterations = CCSDS_RUN_ITERATIONS_DEFAULT;
static uint32_t g_ccsds_run_delay_ms = CCSDS_RUN_DELAY_DEFAULT_MS;

static uint32_t ccsds_check_time_ms(void)
{
    static uint32_t fake_ms = 0U;
    fake_ms += 1U;
    return fake_ms;
}

typedef int32_t (*ccsds_as_check_fn)(void *ctx);

static void ccsds_run_once(ccsds_as_check_fn fn, void *ctx)
{
    if (fn == NULL) {
        return;
    }

    for (uint32_t i = 0U; i < g_ccsds_run_iterations; i++) {
        (void)fn(ctx);
        if (g_ccsds_run_delay_ms > 0U) {
            vTaskDelay(pdMS_TO_TICKS(g_ccsds_run_delay_ms));
        }
    }
}

void ccsds_set_run_iterations(uint32_t iterations)
{
    g_ccsds_run_iterations = (iterations == 0U) ? 1U : iterations;
}

uint32_t ccsds_get_run_iterations(void)
{
    return g_ccsds_run_iterations;
}

void ccsds_set_run_delay_ms(uint32_t delay_ms)
{
    g_ccsds_run_delay_ms = delay_ms;
}

uint32_t ccsds_get_run_delay_ms(void)
{
    return g_ccsds_run_delay_ms;
}

void ccsds_delay_ms(uint32_t delay_ms)
{
    if (delay_ms > 0U) {
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
}

typedef struct {
    uint32_t window_start_ms;
    uint32_t window_failures;
    uint8_t brute_force_active;
    uint8_t index;
} ccsds_as1_state_t;

typedef struct {
    ccsds_as1_state_t tc_state;
    ccsds_as1_state_t tm_state;
} ccsds_as1_combo_state_t;

typedef struct {
    uint32_t window_start_ms;
    uint32_t window_failures;
    uint8_t brute_force_active;
    uint8_t index;
} ccsds_as2_state_t;

typedef struct {
    uint8_t index;
} ccsds_as4_state_t;

typedef struct {
    uint8_t index;
} ccsds_as5_state_t;

static int32_t ccsds_as1_tc_check(void *ctx)
{
    ccsds_as1_state_t *state = (ccsds_as1_state_t *)ctx;
    uint8_t cltu[CCSDS_DEMO_TC_CLTU_MAX_LEN];
    uint8_t sample_idx;
    uint16_t cltu_len;
    uint32_t now_ms;
    int32_t status;

    if (state == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    sample_idx = state->index;
    if (sample_idx >= CCSDS_DEMO_TC_COUNT) {
        sample_idx = 0U;
    }
    cltu_len = g_demo_tc_cltu_len[sample_idx];
    memcpy(cltu, g_demo_tc_cltu[sample_idx], cltu_len);
    state->index = (uint8_t)((sample_idx + 1U) % CCSDS_DEMO_TC_COUNT);

    now_ms = ccsds_check_time_ms();
    if (state->window_start_ms == 0U) {
        state->window_start_ms = now_ms;
    }
    if ((uint32_t)(now_ms - state->window_start_ms) >= CCSDS_DEMO_WINDOW_TICKS) {
        state->window_start_ms = now_ms;
        state->window_failures = 0U;
        state->brute_force_active = 0U;
    }

    status = Check_Packet_CLTU(cltu, cltu_len);
    if (status == CCSDS_CHECK_ERR_INVALID_CLTU_START) {
        state->window_failures++;
        if (state->window_failures > 60U) {
            state->brute_force_active = 1U;
        }
    }

    if (state->brute_force_active != 0U) {
        return CCSDS_CHECK_WARN_BRUTE_FORCE_DETECTED;
    }

    return status;
}

static int32_t ccsds_as1_tm_check(void *ctx)
{
    ccsds_as1_state_t *state = (ccsds_as1_state_t *)ctx;
    uint8_t cltu[sizeof(g_demo_tm_cadu)];
    uint32_t now_ms;
    int32_t status;

    if (state == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    memcpy(cltu, g_demo_tm_cadu, sizeof(cltu));

    now_ms = ccsds_check_time_ms();
    if (state->window_start_ms == 0U) {
        state->window_start_ms = now_ms;
    }
    if ((uint32_t)(now_ms - state->window_start_ms) >= CCSDS_DEMO_WINDOW_TICKS) {
        state->window_start_ms = now_ms;
        state->window_failures = 0U;
        state->brute_force_active = 0U;
    }

    status = Check_Packet_CADU(cltu, (uint16_t)sizeof(cltu));
    if (status == CCSDS_CHECK_ERR_INVALID_CADU_ASM) {
        state->window_failures++;
        if (state->window_failures > 60U) {
            state->brute_force_active = 1U;
        }
    }

    if (state->brute_force_active != 0U) {
        return CCSDS_CHECK_WARN_BRUTE_FORCE_DETECTED;
    }

    return status;
}

static int32_t ccsds_as1_step(void *ctx)
{
    ccsds_as1_combo_state_t *state = (ccsds_as1_combo_state_t *)ctx;
    int32_t tc_status;
    int32_t tm_status;

    if (state == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    tc_status = ccsds_as1_tc_check(&state->tc_state);
    tm_status = ccsds_as1_tm_check(&state->tm_state);

    if (tc_status == CCSDS_CHECK_WARN_BRUTE_FORCE_DETECTED ||
        tm_status == CCSDS_CHECK_WARN_BRUTE_FORCE_DETECTED) {
        return CCSDS_CHECK_WARN_BRUTE_FORCE_DETECTED;
    }
    if (tc_status != CCSDS_CHECK_OK) {
        return tc_status;
    }
    return tm_status;
}

static int32_t ccsds_as2_check(void *ctx)
{
    ccsds_as2_state_t *state = (ccsds_as2_state_t *)ctx;
    uint8_t tf[CCSDS_DEMO_TC_TF_MAX_LEN];
    const uint8_t *tf_src = NULL;
    uint16_t tf_len = 0U;
    uint8_t sample_idx;
    int32_t status;
    uint32_t now_ms;
    uint8_t hdr[4];
    cmd_transfer_frame_header0_type header0;
    cmd_transfer_frame_header1_type header1;

    if (state == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    sample_idx = state->index;
    if (sample_idx >= CCSDS_DEMO_TC_COUNT) {
        sample_idx = 0U;
    }
    tf_src = g_demo_tc_tf[sample_idx];
    tf_len = g_demo_tc_tf_len[sample_idx];
    state->index = (uint8_t)((sample_idx + 1U) % CCSDS_DEMO_TC_COUNT);
    if (tf_len > (uint16_t)sizeof(tf)) {
        status = CCSDS_CHECK_ERR_INVALID_LENGTH;
        goto as2_done;
    }
    memcpy(tf, tf_src, tf_len);

    now_ms = ccsds_check_time_ms();
    if (state->window_start_ms == 0U) {
        state->window_start_ms = now_ms;
    }
    if ((uint32_t)(now_ms - state->window_start_ms) >= CCSDS_DEMO_WINDOW_TICKS) {
        state->window_start_ms = now_ms;
        state->window_failures = 0U;
        state->brute_force_active = 0U;
    }

    if (tf_len < 4U) {
        status = CCSDS_CHECK_ERR_INVALID_LENGTH;
        goto as2_done;
    }

    /* Partial de-randomization: only header bytes needed for checks */
    for (uint16_t i = 0U; i < 4U; i++) {
        hdr[i] = (uint8_t)(tf[i] ^ ccsds_randomization_sequence[i]);
    }

    header0.whole = (uint16_t)((hdr[0] << 8) | hdr[1]);
    header1.whole = (uint16_t)((hdr[2] << 8) | hdr[3]);

    if ((header0.bits.ver != 0U) ||
        (header0.bits.scid != 1U) ||
        (header1.bits.flength != (uint16_t)(tf_len - 1U))) {
        status = CCSDS_CHECK_ERR_INVALID_RANDOMIZATION;
        state->window_failures++;
        if (state->window_failures > 60U) {
            state->brute_force_active = 1U;
        }
    } else {
        status = CCSDS_CHECK_OK;
    }

as2_done:
    if (state->brute_force_active != 0U) {
        return CCSDS_CHECK_WARN_RANDOMIZATION_BRUTE_FORCE;
    }

    return status;
}

static int32_t ccsds_as4_check(void *ctx)
{
    ccsds_as4_state_t *state = (ccsds_as4_state_t *)ctx;
    const uint8_t *spp = NULL;
    uint16_t spp_len = 0U;
    uint8_t sample_idx;
    spp_payload_analysis_t ecb_analysis;
    int32_t ecb_status;
    float entropy;
    float entropy_score;

    if (state == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    sample_idx = state->index;
    if (sample_idx >= CCSDS_DEMO_TC_COUNT) {
        sample_idx = 0U;
    }
    spp = g_demo_tc_spp[sample_idx];
    spp_len = g_demo_tc_spp_len[sample_idx];
    state->index = (uint8_t)((sample_idx + 1U) % CCSDS_DEMO_TC_COUNT);

    if (spp_len <= 6U) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    ecb_status = Analyze_SPP_ECB_Pattern(&spp[6], (uint16_t)(spp_len - 6U), &ecb_analysis);
    if (ecb_status < 0) {
        return ecb_status;
    }

    entropy = Calculate_Payload_Entropy(&spp[6], (uint16_t)(spp_len - 6U));
    if (entropy < 0.0f) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }
    entropy_score = (8.0f - entropy) / 8.0f;

    if (ecb_status == CCSDS_CHECK_WARN_ECB_PATTERN_DETECTED) {
        return ecb_status;
    }
    if (entropy_score > 0.6f) {
        return CCSDS_CHECK_WARN_PLAINTEXT_DETECTED;
    }

    return CCSDS_CHECK_OK;
}

static int32_t ccsds_as5_check(void *ctx)
{
    ccsds_as5_state_t *state = (ccsds_as5_state_t *)ctx;
    const uint8_t *tf = NULL;
    uint16_t tf_len = 0U;
    uint16_t spp_len = 0U;
    uint8_t sample_idx;
    cmd_transfer_frame_header1_type header1;
    uint16_t declared_tf_len;

    if (state == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    sample_idx = state->index;
    if (sample_idx >= CCSDS_DEMO_TC_COUNT) {
        sample_idx = 0U;
    }
    tf = g_demo_tc_tf[sample_idx];
    tf_len = g_demo_tc_tf_len[sample_idx];
    spp_len = g_demo_tc_spp_len[sample_idx];
    state->index = (uint8_t)((sample_idx + 1U) % CCSDS_DEMO_TC_COUNT);

    if (tf_len < 4U || spp_len < 6U) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }

    header1.whole = (uint16_t)((((uint16_t)tf[2]) << 8) | (uint16_t)tf[3]);
    declared_tf_len = (uint16_t)(header1.bits.flength + 1U);

    if (declared_tf_len != tf_len) {
        return CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH;
    }

    if (tf_len != (uint16_t)(spp_len + 7U)) {
        return CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH;
    }

    if (header1.bits.flength != (uint16_t)(spp_len + 6U)) {
        return CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH;
    }

    return CCSDS_CHECK_OK;
}

typedef struct {
    cop1_farm1_state_t farm[64];
    uint32_t window_start_ms[64];
    uint16_t replay_count[64];
    uint16_t jump_count[64];
    uint8_t suspicious[64];
    uint8_t index;
} ccsds_as6_state_t;

#define CCSDS_AS6_DUP_WINDOW_MS 1000U
#define CCSDS_AS6_DUP_MAX        5U
#define CCSDS_AS6_JUMP_MAX       3U

static int32_t ccsds_as6_check(void *ctx)
{
    ccsds_as6_state_t *state = (ccsds_as6_state_t *)ctx;
    uint8_t tf[CCSDS_DEMO_TC_TF_MAX_LEN];
    const uint8_t *tf_src = NULL;
    uint16_t tf_len = 0U;
    uint8_t sample_idx;
    int32_t status;
    uint32_t now_ms;
    tc_tf_header_t header;
    uint8_t vcid;

    if (state == NULL) {
        return CCSDS_CHECK_ERR_NULL_POINTER;
    }

    sample_idx = state->index;
    if (sample_idx >= CCSDS_DEMO_TC_COUNT) {
        sample_idx = 0U;
    }
    tf_src = g_demo_tc_tf[sample_idx];
    tf_len = g_demo_tc_tf_len[sample_idx];
    state->index = (uint8_t)((sample_idx + 1U) % CCSDS_DEMO_TC_COUNT);

    if (tf_len > (uint16_t)sizeof(tf)) {
        return CCSDS_CHECK_ERR_INVALID_LENGTH;
    }
    memcpy(tf, tf_src, tf_len);

    status = Parse_TC_TF_Header(tf, tf_len, &header);
    if (status != CCSDS_CHECK_OK) {
        return status;
    }

    vcid = header.vcid;
    if (vcid >= 64U) {
        return CCSDS_CHECK_ERR_INVALID_TF_HEADER;
    }

    status = cop1_farm1_on_ad(&state->farm[vcid], header.seq_num);
    now_ms = ccsds_check_time_ms();
    if (state->window_start_ms[vcid] == 0U) {
        state->window_start_ms[vcid] = now_ms;
    }
    if ((uint32_t)(now_ms - state->window_start_ms[vcid]) >= CCSDS_AS6_DUP_WINDOW_MS) {
        state->window_start_ms[vcid] = now_ms;
        state->replay_count[vcid] = 0U;
        state->jump_count[vcid] = 0U;
        state->suspicious[vcid] = 0U;
    }

    if (status == CCSDS_CHECK_ERR_REPLAY_ATTACK) {
        state->replay_count[vcid]++;
        if (state->replay_count[vcid] > CCSDS_AS6_DUP_MAX) {
            state->suspicious[vcid] = 1U;
        }
    } else if (status == CCSDS_CHECK_ERR_SEQUENCE_MISMATCH) {
        state->jump_count[vcid]++;
        if (state->jump_count[vcid] > CCSDS_AS6_JUMP_MAX) {
            state->suspicious[vcid] = 1U;
        }
    }

    if (state->suspicious[vcid] != 0U) {
        return CCSDS_CHECK_WARN_REPLAY_SUSPICIOUS;
    }

    return status;
}


void ccsds_run_as1(void)
{
    ccsds_as1_combo_state_t state = {{0U, 0U, 0U, 0U}, {0U, 0U, 0U, 0U}};
    ccsds_run_once(ccsds_as1_step, &state);
}

void ccsds_run_as2(void)
{
    ccsds_as2_state_t state = {0U, 0U, 0U, 0U};
    ccsds_run_once(ccsds_as2_check, &state);
}

void ccsds_run_as3(void)
{
    /* AS-3 check removed from this module; keep stub for compatibility. */
}

void ccsds_run_as4(void)
{
    ccsds_as4_state_t state = {0U};
    ccsds_run_once(ccsds_as4_check, &state);
}

void ccsds_run_as5(void)
{
    ccsds_as5_state_t state = {0U};
    ccsds_run_once(ccsds_as5_check, &state);
}

static ccsds_as6_state_t s_as6_state;

void ccsds_reset_as6_state(void)
{
    memset(&s_as6_state, 0, sizeof(s_as6_state));
}

void ccsds_run_as6(void)
{
    ccsds_run_once(ccsds_as6_check, &s_as6_state);
}
