/**
 * @file ccsds_packet_check.h
 * @brief CCSDS Packet Validation and Randomization Compliance Checker
 * 
 * This header file provides functions for validating CCSDS packet structures
 * including:
 * 1. Start-Sequence/TM-Sync marker validation (0xEB90 for CLTU, 0x1ACFFC1D for CADU)
 * 2. CCSDS Randomization/DeRandomization compliance checking
 * 3. Transfer Frame extraction and validation
 * 
 * @author MESL
 * @date 2025
 */

#ifndef CCSDS_PACKET_CHECK_H
#define CCSDS_PACKET_CHECK_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===================================================================== */
/* Constants and Definitions                                            */
/* ===================================================================== */

/** @brief CLTU Start Sequence value */
#define CLTU_START_SEQ_0 0xEB
#define CLTU_START_SEQ_1 0x90
#define CLTU_START_SEQ (0xEB90)

/** @brief CADU Header (Attached Sync Marker) value */
#define CADU_ASM (0x1ACFFC1D)

/** @brief CCSDS Randomization sequence length */
#define CCSDS_RAND_SEQ_LEN 255

/** @brief Code block size in CLTU (7 bytes data + 1 byte ECC) */
#define CLTU_CODE_BLOCK_SIZE 8

/** @brief Tail sequence for CLTU */
#define CLTU_TAIL_SEQ_0 0xC5
#define CLTU_TAIL_SEQ_1 0xC5
#define CLTU_TAIL_SEQ_2 0xC5
#define CLTU_TAIL_SEQ_3 0xC5
#define CLTU_TAIL_SEQ_4 0xC5
#define CLTU_TAIL_SEQ_5 0xC5
#define CLTU_TAIL_SEQ_6 0xC5
#define CLTU_TAIL_SEQ_7 0x79

/** @brief Error/Status codes */
typedef enum {
    CCSDS_CHECK_OK = 0,                          /*!< Success */
    CCSDS_CHECK_ERR_NULL_POINTER = -1,           /*!< Null pointer provided */
    CCSDS_CHECK_ERR_INVALID_LENGTH = -2,         /*!< Invalid packet length */
    CCSDS_CHECK_ERR_INVALID_CLTU_START = -3,     /*!< Invalid CLTU start sequence */
    CCSDS_CHECK_ERR_INVALID_CLTU_TAIL = -4,      /*!< Invalid CLTU tail sequence */
    CCSDS_CHECK_ERR_INVALID_CADU_ASM = -5,       /*!< Invalid CADU ASM */
    CCSDS_CHECK_ERR_INVALID_RANDOMIZATION = -6,  /*!< CCSDS randomization check failed */
    CCSDS_CHECK_ERR_TF_EXTRACTION_FAILED = -7,   /*!< Transfer Frame extraction failed */
    CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH = -8, /*!< Header length doesn't match payload */
    CCSDS_CHECK_ERR_REPLAY_ATTACK = -9,          /*!< Possible replay attack detected */
    CCSDS_CHECK_ERR_SEQUENCE_MISMATCH = -10,     /*!< Sequence number mismatch */
    CCSDS_CHECK_ERR_DECODING_FAILED = -11,       /*!< TF decoding failed */
    CCSDS_CHECK_ERR_INVALID_TF_HEADER = -12,     /*!< Invalid Transfer Frame header fields */
    CCSDS_CHECK_ERR_INVALID_SPP_HEADER = -13,    /*!< Invalid SPP header fields */
    CCSDS_CHECK_WARN_PLAINTEXT_DETECTED = 1,     /*!< Warning: Plaintext payload detected (AS-5) */
    CCSDS_CHECK_WARN_ECB_PATTERN_DETECTED = 2,   /*!< Warning: ECB block repetition detected (AS-4) */
    CCSDS_CHECK_WARN_BRUTE_FORCE_DETECTED = 3,   /*!< Warning: CLTU start brute-force detected (AS-1) */
    CCSDS_CHECK_WARN_RANDOMIZATION_BRUTE_FORCE = 4, /*!< Warning: randomization brute-force detected (AS-2) */
    CCSDS_CHECK_WARN_REPLAY_SUSPICIOUS = 5,     /*!< Warning: excessive replay indications detected (AS-6) */
} ccsds_check_status_t;

/* ===================================================================== */
/* Transfer Frame Header Structures                                      */
/* ===================================================================== */

/**
 * @brief TC Transfer Frame Header (Primary)
 * 
 * Structure for parsing TC (Telecommand) Transfer Frame headers
 */
typedef struct {
    uint16_t scid;              /*!< Spacecraft ID (10 bits) */
    uint8_t vcid;               /*!< Virtual Channel ID (3 bits) */
    uint8_t seq_num;            /*!< Frame Sequence Number */
} tc_tf_header_t;

/**
 * @brief TM Transfer Frame Header (Primary)
 * 
 * Structure for parsing TM (Telemetry) Transfer Frame headers
 */
typedef struct {
    uint16_t scid;              /*!< Spacecraft ID (10 bits) */
    uint8_t vcid;               /*!< Virtual Channel ID (3 bits) */
    uint16_t mcfc;              /*!< Master Channel Frame Count (sequence number) */
} tm_tf_header_t;

/**
 * @brief CCSDS SPP (Space Packet Protocol) Header
 * 
 * Structure for parsing SPP packet headers
 */
typedef struct {
    uint16_t stream_id;         /*!< Stream ID (Apid + flags) */
    uint16_t seq_count;         /*!< Sequence Counter */
    uint16_t pkt_length;        /*!< Packet Length (total length - 1) */
} ccsds_spp_header_t;

/**
 * @brief SPP Payload Analysis Result
 * 
 * Results from analyzing SPP payload for encryption/plaintext detection
 */
typedef struct {
    float entropy;              /*!< Shannon entropy (0-8 bits) */
    float ascii_ratio;          /*!< Printable ASCII ratio (0.0-1.0) */
    uint16_t ecb_repeats;       /*!< Number of repeated 4-byte blocks */
    float plaintext_score;      /*!< Plaintext likelihood score (0.0-1.0) */
    float ecb_score;            /*!< ECB pattern score (0.0-1.0) */
} spp_payload_analysis_t;

/* ===================================================================== */
/* CCSDS Randomization Sequence                                         */
/* ===================================================================== */

/**
 * @brief CCSDS Randomization sequence (255 bytes)
 * 
 * This is the standard CCSDS pseudo-random sequence used for
 * randomizing/de-randomizing transfer frames according to
 * CCSDS 131.0-B-3 specification.
 */
static const uint8_t ccsds_randomization_sequence[CCSDS_RAND_SEQ_LEN] = {
    0xFF, 0x48, 0x0E, 0xC0, 0x9A, 0x0D, 0x70, 0xBC,
    0x8E, 0x2C, 0x93, 0xAD, 0xA7, 0xB7, 0x46, 0xCE,
    0x5A, 0x97, 0x7D, 0xCC, 0x32, 0xA2, 0xBF, 0x3E,
    0x0A, 0x10, 0xF1, 0x88, 0x94, 0xCD, 0xEA, 0xB1,
    0xFE, 0x90, 0x1D, 0x81, 0x34, 0x1A, 0xE1, 0x79,
    0x1C, 0x59, 0x27, 0x5B, 0x4F, 0x6E, 0x8D, 0x9C,
    0xB5, 0x2E, 0xFB, 0x98, 0x65, 0x45, 0x7E, 0x7C,
    0x14, 0x21, 0xE3, 0x11, 0x29, 0x9B, 0xD5, 0x63,
    0xFD, 0x20, 0x3B, 0x02, 0x68, 0x35, 0xC2, 0xF2,
    0x38, 0xB2, 0x4E, 0xB6, 0x9E, 0xDD, 0x1B, 0x39,
    0x6A, 0x5D, 0xF7, 0x30, 0xCA, 0x8A, 0xFC, 0xF8,
    0x28, 0x43, 0xC6, 0x22, 0x53, 0x37, 0xAA, 0xC7,
    0xFA, 0x40, 0x76, 0x04, 0xD0, 0x6B, 0x85, 0xE4,
    0x71, 0x64, 0x9D, 0x6D, 0x3D, 0xBA, 0x36, 0x72,
    0xD4, 0xBB, 0xEE, 0x61, 0x95, 0x15, 0xF9, 0xF0,
    0x50, 0x87, 0x8C, 0x44, 0xA6, 0x6F, 0x55, 0x8F,
    0xF4, 0x80, 0xEC, 0x09, 0xA0, 0xD7, 0x0B, 0xC8,
    0xE2, 0xC9, 0x3A, 0xDA, 0x7B, 0x74, 0x6C, 0xE5,
    0xA9, 0x77, 0xDC, 0xC3, 0x2A, 0x2B, 0xF3, 0xE0,
    0xA1, 0x0F, 0x18, 0x89, 0x4C, 0xDE, 0xAB, 0x1F,
    0xE9, 0x01, 0xD8, 0x13, 0x41, 0xAE, 0x17, 0x91,
    0xC5, 0x92, 0x75, 0xB4, 0xF6, 0xE8, 0xD9, 0xCB,
    0x52, 0xEF, 0xB9, 0x86, 0x54, 0x57, 0xE7, 0xC1,
    0x42, 0x1E, 0x31, 0x12, 0x99, 0xBD, 0x56, 0x3F,
    0xD2, 0x03, 0xB0, 0x26, 0x83, 0x5C, 0x2F, 0x23,
    0x8B, 0x24, 0xEB, 0x69, 0xED, 0xD1, 0xB3, 0x96,
    0xA5, 0xDF, 0x73, 0x0C, 0xA8, 0xAF, 0xCF, 0x82,
    0x84, 0x3C, 0x62, 0x25, 0x33, 0x7A, 0xAC, 0x7F,
    0xA4, 0x07, 0x60, 0x4D, 0x06, 0xB8, 0x5E, 0x47,
    0x16, 0x49, 0xD6, 0xD3, 0xDB, 0xA3, 0x67, 0x2D,
    0x4B, 0xBE, 0xE6, 0x19, 0x51, 0x5F, 0x9F, 0x05,
    0x08, 0x78, 0xC4, 0x4A, 0x66, 0xF5, 0x58
};

/* ===================================================================== */
/* Function Declarations                                                */
/* ===================================================================== */

/**
 * @brief Check CLTU (Command Link Transfer Unit) Start Sequence
 * 
 * Validates that the first two bytes of a CLTU packet are the correct
 * start sequence value (0xEB 0x90).
 * 
 * @param[in] data_cltu Pointer to CLTU packet data
 * @param[in] cltu_len  Length of CLTU packet
 * 
 * @return CCSDS_CHECK_OK if start sequence is valid
 * @return CCSDS_CHECK_ERR_NULL_POINTER if data_cltu is NULL
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if cltu_len < 2
 * @return CCSDS_CHECK_ERR_INVALID_CLTU_START if start sequence doesn't match
 */
int32_t Check_Packet_CLTU(const uint8_t *data_cltu, uint16_t cltu_len);

/**
 * @brief Check CADU (Channel Access Data Unit) Header (ASM - Attached Sync Marker)
 * 
 * Validates that the first 4 bytes of a CADU packet are the correct
 * ASM value (0x1A 0xCF 0xFC 0x1D).
 * 
 * @param[in] data_cadu Pointer to CADU packet data
 * @param[in] cadu_len  Length of CADU packet
 * 
 * @return CCSDS_CHECK_OK if ASM is valid
 * @return CCSDS_CHECK_ERR_NULL_POINTER if data_cadu is NULL
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if cadu_len < 4
 * @return CCSDS_CHECK_ERR_INVALID_CADU_ASM if ASM doesn't match
 */
int32_t Check_Packet_CADU(const uint8_t *data_cadu, uint16_t cadu_len);

/**
 * @brief Apply CCSDS De-Randomization to data
 * 
 * De-randomizes data using the standard CCSDS randomization sequence.
 * This is typically used on received Transfer Frames that have been randomized.
 * 
 * @param[in,out] data   Pointer to data buffer to de-randomize
 * @param[in]     length Length of data to de-randomize
 * 
 * @return CCSDS_CHECK_OK on success
 * @return CCSDS_CHECK_ERR_NULL_POINTER if data is NULL
 */
int32_t CCSDS_DeRandomize(uint8_t *data, uint16_t length);

/**
 * @brief Apply CCSDS Randomization to data
 * 
 * Randomizes data using the standard CCSDS randomization sequence.
 * This is typically used on Transfer Frames before transmission.
 * 
 * @param[in,out] data   Pointer to data buffer to randomize
 * @param[in]     length Length of data to randomize
 * 
 * @return CCSDS_CHECK_OK on success
 * @return CCSDS_CHECK_ERR_NULL_POINTER if data is NULL
 */
int32_t CCSDS_Randomize(uint8_t *data, uint16_t length);

/**
 * @brief Check CCSDS Randomization in Transfer Frame
 * 
 * Verifies that a Transfer Frame contains valid CCSDS randomization pattern.
 * This checks if the frame was properly randomized by comparing against
 * expected randomization values.
 * 
 * @param[in] data_tframe Pointer to transfer frame data
 * @param[in] tframe_len  Length of transfer frame
 * @param[in] randomized  Whether frame should be randomized (true) or not (false)
 * 
 * @return CCSDS_CHECK_OK if randomization is valid
 * @return CCSDS_CHECK_ERR_NULL_POINTER if data_tframe is NULL
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if tframe_len is 0
 * @return CCSDS_CHECK_ERR_INVALID_RANDOMIZATION if randomization doesn't match
 */
int32_t Check_CCSDS_Randomization(const uint8_t *data_tframe, 
                                  uint16_t tframe_len, bool randomized);

/**
 * @brief Extract Transfer Frame from CLTU and validate
 * 
 * Extracts the Transfer Frame (TF) data from a CLTU packet.
 * Validates CLTU structure (start sequence, tail sequence, code blocks).
 * Optionally applies de-randomization to extracted frame.
 * 
 * @param[out] tframe_data   Pointer to buffer for extracted transfer frame
 * @param[out] tframe_len    Pointer to store extracted frame length
 * @param[in]  tframe_maxlen Maximum size of tframe_data buffer
 * @param[in]  cltu_data     Pointer to CLTU packet data
 * @param[in]  cltu_len      Length of CLTU packet
 * @param[in]  apply_derand  Whether to apply de-randomization (true) or not (false)
 * 
 * @return CCSDS_CHECK_OK if extraction successful
 * @return CCSDS_CHECK_ERR_NULL_POINTER if any pointer is NULL
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if lengths are invalid
 * @return CCSDS_CHECK_ERR_INVALID_CLTU_START if CLTU start sequence invalid
 * @return CCSDS_CHECK_ERR_INVALID_CLTU_TAIL if CLTU tail sequence not found
 * @return CCSDS_CHECK_ERR_TF_EXTRACTION_FAILED if extraction failed
 */
int32_t Extract_TF_From_CLTU(uint8_t *tframe_data, uint16_t *tframe_len,
                             uint16_t tframe_maxlen,
                             const uint8_t *cltu_data, uint16_t cltu_len,
                             bool apply_derand);

/**
 * @brief Extract Transfer Frame from CADU and validate
 *
 * Extracts the Transfer Frame (TF) data from a CADU packet.
 * Validates CADU ASM and optionally applies de-randomization.
 *
 * @param[out] tframe_data   Pointer to buffer for extracted transfer frame
 * @param[out] tframe_len    Pointer to store extracted frame length
 * @param[in]  tframe_maxlen Maximum size of tframe_data buffer
 * @param[in]  cadu_data     Pointer to CADU packet data (ASM + TF)
 * @param[in]  cadu_len      Length of CADU packet
 * @param[in]  apply_derand  Whether to apply de-randomization (true) or not (false)
 *
 * @return CCSDS_CHECK_OK if extraction successful
 * @return CCSDS_CHECK_ERR_NULL_POINTER if any pointer is NULL
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if lengths are invalid
 * @return CCSDS_CHECK_ERR_INVALID_CADU_ASM if CADU ASM invalid
 */
int32_t Extract_TF_From_CADU(uint8_t *tframe_data, uint16_t *tframe_len,
                             uint16_t tframe_maxlen,
                             const uint8_t *cadu_data, uint16_t cadu_len,
                             bool apply_derand);

/**
 * @brief Verify Transfer Frame Decoding with CCSDS Randomization
 * 
 * Decodes CADU to Transfer Frame and verifies CCSDS randomization was applied.
 * Compares extracted TF with expected TF to validate randomization compliance.
 * 
 * @param[in]  cadu_data      Pointer to CADU packet data (4 byte ASM + TF data)
 * @param[in]  cadu_len       Length of CADU packet (typically 324 bytes)
 * @param[in]  expected_tf    Pointer to expected Transfer Frame data for comparison
 * @param[in]  expected_tf_len Length of expected TF
 * @param[out] extracted_tf   Pointer to buffer for extracted TF (optional, can be NULL)
 * @param[out] extracted_tf_len Pointer to store extracted TF length (optional)
 * 
 * @return CCSDS_CHECK_OK if decoding successful and randomization verified
 * @return CCSDS_CHECK_ERR_INVALID_CADU_ASM if ASM invalid
 * @return CCSDS_CHECK_ERR_INVALID_RANDOMIZATION if TF mismatch detected
 * @return CCSDS_CHECK_ERR_DECODING_FAILED if decoding failed
 */
int32_t Verify_TF_Decoding_With_Randomization(
    const uint8_t *cadu_data, uint16_t cadu_len,
    const uint8_t *expected_tf, uint16_t expected_tf_len,
    uint8_t *extracted_tf, uint16_t *extracted_tf_len);

/**
 * @brief Verify SPP (Space Packet Protocol) Header Length
 * 
 * Parses SPP packet header and verifies the declared packet length
 * matches the actual payload size.
 * 
 * @param[in]  spp_packet     Pointer to SPP packet data
 * @param[in]  packet_size    Actual size of SPP packet
 * @param[out] header         Pointer to SPP header structure (optional, can be NULL)
 * 
 * @return CCSDS_CHECK_OK if header length matches payload
 * @return CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH if length doesn't match
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if packet too short for header
 */
int32_t Verify_SPP_Header_Length(const uint8_t *spp_packet, uint16_t packet_size,
                                 ccsds_spp_header_t *header);

/**
 * @brief Verify Transfer Frame Header Length
 * 
 * Parses Transfer Frame header and verifies declared frame size
 * matches actual frame data.
 * 
 * @param[in]  tf_packet      Pointer to Transfer Frame data
 * @param[in]  frame_size     Actual size of Transfer Frame
 * @param[out] tc_header      Pointer to TC TF header (optional)
 * 
 * @return CCSDS_CHECK_OK if header length matches frame size
 * @return CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH if size doesn't match
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if frame too short
 */
int32_t Verify_TF_Header_Length(const uint8_t *tf_packet, uint16_t frame_size,
                                tc_tf_header_t *tc_header);

/**
 * @brief Verify TM Transfer Frame Header Length
 *
 * Parses TM Transfer Frame header and verifies frame size is reasonable.
 *
 * @param[in]  tf_packet      Pointer to Transfer Frame data
 * @param[in]  frame_size     Actual size of Transfer Frame
 * @param[out] tm_header      Pointer to TM TF header (optional)
 *
 * @return CCSDS_CHECK_OK if header length matches frame size
 * @return CCSDS_CHECK_ERR_HEADER_LENGTH_MISMATCH if size doesn't match
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if frame too short
 */
int32_t Verify_TM_TF_Header_Length(const uint8_t *tf_packet, uint16_t frame_size,
                                   tm_tf_header_t *tm_header);

/**
 * @brief Verify TC Transfer Frame Header Fields
 *
 * Validates parsed TC TF header fields (SCID/VCID ranges, etc.).
 *
 * @param[in] header Pointer to TC TF header
 *
 * @return CCSDS_CHECK_OK if fields are valid
 * @return CCSDS_CHECK_ERR_INVALID_TF_HEADER if fields are invalid
 * @return CCSDS_CHECK_ERR_NULL_POINTER if header is NULL
 */
int32_t Verify_TC_TF_Header_Fields(const tc_tf_header_t *header);

/**
 * @brief Verify TM Transfer Frame Header Fields
 *
 * Validates parsed TM TF header fields (SCID/VCID/MCFC ranges, etc.).
 *
 * @param[in] header Pointer to TM TF header
 *
 * @return CCSDS_CHECK_OK if fields are valid
 * @return CCSDS_CHECK_ERR_INVALID_TF_HEADER if fields are invalid
 * @return CCSDS_CHECK_ERR_NULL_POINTER if header is NULL
 */
int32_t Verify_TM_TF_Header_Fields(const tm_tf_header_t *header);

/**
 * @brief Verify SPP Header Fields
 *
 * Validates SPP primary header fields (version/type/APID/seq flags).
 *
 * @param[in] header Pointer to SPP header
 * @param[in] expect_tc Whether to enforce TC packet type (true) or TM (false)
 *
 * @return CCSDS_CHECK_OK if fields are valid
 * @return CCSDS_CHECK_ERR_INVALID_SPP_HEADER if fields are invalid
 * @return CCSDS_CHECK_ERR_NULL_POINTER if header is NULL
 */
int32_t Verify_SPP_Header_Fields(const ccsds_spp_header_t *header, bool expect_tc);

/**
 * @brief Detect Replay Attack via Sequence Number
 * 
 * Compares expected Frame Sequence Number with actual received sequence.
 * Detects replay attacks where older packets are replayed.
 * 
 * @param[in] expected_seq    Expected Frame Sequence Number
 * @param[in] received_seq    Actual received Frame Sequence Number
 * @param[in] is_tm           Whether this is TM (true) or TC (false)
 * 
 * @return CCSDS_CHECK_OK if sequence is valid (received_seq > expected_seq)
 * @return CCSDS_CHECK_ERR_REPLAY_ATTACK if received_seq <= expected_seq (suspicious)
 * @return CCSDS_CHECK_ERR_SEQUENCE_MISMATCH if sequence gap too large (>100)
 */

/**
 * @brief Calculate Shannon entropy of data
 * 
 * @param[in] data   Pointer to data buffer
 * @param[in] length Length of data
 * 
 * @return Shannon entropy in bits (0.0 to 8.0)
 * @return -1.0 on error
 */
float Calculate_Payload_Entropy(const uint8_t *data, uint16_t length);

/**
 * @brief Calculate printable ASCII ratio in data
 * 
 * @param[in] data   Pointer to data buffer
 * @param[in] length Length of data
 * 
 * @return Ratio of printable ASCII characters (0.0 to 1.0)
 * @return -1.0 on error
 */
float Calculate_ASCII_Ratio(const uint8_t *data, uint16_t length);

/**
 * @brief Detect repeated 16-byte blocks (ECB pattern)
 * 
 * @param[in] data   Pointer to data buffer
 * @param[in] length Length of data
 * 
 * @return Number of repeated 16-byte blocks found
 * @return 0 if no repetitions or error
 */
uint16_t Detect_ECB_Block_Repetition(const uint8_t *data, uint16_t length);

/**
 * @brief Analyze SPP payload for ECB patterns (AS-4)
 *
 * @param[in]  payload  Pointer to SPP payload (after 6-byte SPP header)
 * @param[in]  length   Length of payload
 * @param[out] result   Analysis result structure
 *
 * @return CCSDS_CHECK_OK if analysis completed
 * @return CCSDS_CHECK_WARN_ECB_PATTERN_DETECTED if ECB pattern detected (AS-4)
 * @return CCSDS_CHECK_ERR_NULL_POINTER on error
 */
int32_t Analyze_SPP_ECB_Pattern(const uint8_t *payload, uint16_t length,
                                spp_payload_analysis_t *result);

/**
 * @brief Analyze SPP payload for plaintext patterns (AS-5)
 *
 * @param[in]  payload  Pointer to SPP payload (after 6-byte SPP header)
 * @param[in]  length   Length of payload
 * @param[out] result   Analysis result structure
 *
 * @return CCSDS_CHECK_OK if analysis completed
 * @return CCSDS_CHECK_WARN_PLAINTEXT_DETECTED if plaintext suspected (AS-5)
 * @return CCSDS_CHECK_ERR_NULL_POINTER on error
 */
int32_t Analyze_SPP_Plaintext(const uint8_t *payload, uint16_t length,
                              spp_payload_analysis_t *result);

/**
 * @brief Parse TC Transfer Frame Header
 * 
 * Extracts SCID, VCID, and Sequence Number from TC TF header.
 * 
 * @param[in]  tf_data        Pointer to TC Transfer Frame data
 * @param[in]  tf_len         Length of Transfer Frame
 * @param[out] header         Pointer to tc_tf_header_t structure
 * 
 * @return CCSDS_CHECK_OK if parsing successful
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if TF too short
 * @return CCSDS_CHECK_ERR_NULL_POINTER if pointer is NULL
 */
int32_t Parse_TC_TF_Header(const uint8_t *tf_data, uint16_t tf_len,
                           tc_tf_header_t *header);

/**
 * @brief Parse TM Transfer Frame Header
 * 
 * Extracts SCID, VCID, and MCFC (Master Channel Frame Count) from TM TF header.
 * 
 * @param[in]  tf_data        Pointer to TM Transfer Frame data
 * @param[in]  tf_len         Length of Transfer Frame
 * @param[out] header         Pointer to tm_tf_header_t structure
 * 
 * @return CCSDS_CHECK_OK if parsing successful
 * @return CCSDS_CHECK_ERR_INVALID_LENGTH if TF too short
 * @return CCSDS_CHECK_ERR_NULL_POINTER if pointer is NULL
 */
int32_t Parse_TM_TF_Header(const uint8_t *tf_data, uint16_t tf_len,
                           tm_tf_header_t *header);

/**
 * @brief Print error message for given status code
 * 
 * @param[in] status Status code from check functions
 * 
 * @return Pointer to static error message string
 */
const char* CCSDS_GetErrorMessage(int32_t status);

/* ===================================================================== */
/* Decoding Pipelines - High-level Functions                           */
/* ===================================================================== */

/**
 * @brief Decode TC CLTU packet through complete pipeline
 * 
 * Performs complete decoding pipeline: CLTU → TFRAME → SPP
 * 
 * Flow:
 *   1. Validate CLTU start sequence (0xEB90)
 *   2. Extract Transfer Frame from CLTU (detect tail sequence)
 *   3. De-randomize Transfer Frame
 *   4. Parse Transfer Frame header (get SCID, VCID, Seq)
 *   5. Validate SPP header length vs payload size
 *   6. Extract and return SPP packet
 * 
 * @param[in]  cltu_data        Pointer to TC CLTU packet
 * @param[in]  cltu_len         Length of CLTU packet
 * @param[out] spp_out          Buffer for extracted SPP packet
 * @param[in]  spp_max_len      Maximum size of spp_out buffer
 * @param[out] spp_len          Pointer to store extracted SPP length
 * @param[out] tf_header        Pointer to TC TF header (optional, can be NULL)
 * 
 * @return CCSDS_CHECK_OK if entire pipeline successful
 * @return Error code if any step fails (see enum ccsds_check_status_t)
 */
int32_t Decode_TC_CLTU_Pipeline(const uint8_t *cltu_data, uint16_t cltu_len,
                                 uint8_t *spp_out, uint16_t spp_max_len,
                                 uint16_t *spp_len, tc_tf_header_t *tf_header);

/**
 * @brief Decode TM CADU packet through complete pipeline
 * 
 * Performs complete decoding pipeline: CADU → TFRAME → SPP
 * 
 * Flow:
 *   1. Validate CADU ASM (0x1ACFFC1D)
 *   2. Extract Transfer Frame from CADU
 *   3. De-randomize Transfer Frame
 *   4. Parse Transfer Frame header (get SCID, VCID, MCFC)
 *   5. Validate SCID/VCID (optional, can be skipped)
 *   6. Validate SPP header length vs payload size
 *   7. Extract and return SPP packet
 * 
 * @param[in]  cadu_data        Pointer to TM CADU packet
 * @param[in]  cadu_len         Length of CADU packet (typically 324)
 * @param[out] spp_out          Buffer for extracted SPP packet
 * @param[in]  spp_max_len      Maximum size of spp_out buffer
 * @param[out] spp_len          Pointer to store extracted SPP length
 * @param[out] tf_header        Pointer to TM TF header (optional, can be NULL)
 * 
 * @return CCSDS_CHECK_OK if entire pipeline successful
 * @return Error code if any step fails (see enum ccsds_check_status_t)
 */
int32_t Decode_TM_CADU_Pipeline(const uint8_t *cadu_data, uint16_t cadu_len,
                                 uint8_t *spp_out, uint16_t spp_max_len,
                                 uint16_t *spp_len, tm_tf_header_t *tf_header);

/**
 * @brief Print CLTU packet structure in formatted output
 * 
 * @param[in] data_cltu Pointer to CLTU packet data
 * @param[in] cltu_len  Length of CLTU packet
 * @param[in] fp        File pointer for output (NULL for stdout)
 */
void Print_CLTU_Structure(const uint8_t *data_cltu, uint16_t cltu_len, FILE *fp);

/**
 * @brief Print CADU packet structure in formatted output
 * 
 * @param[in] data_cadu Pointer to CADU packet data
 * @param[in] cadu_len  Length of CADU packet
 * @param[in] fp        File pointer for output (NULL for stdout)
 */
void Print_CADU_Structure(const uint8_t *data_cadu, uint16_t cadu_len, FILE *fp);

/**
 * @brief Print hex dump of data
 * 
 * @param[in] title     Title/label for the hex dump
 * @param[in] data      Pointer to data buffer
 * @param[in] len       Length of data
 * @param[in] fp        File pointer for output (NULL for stdout)
 */
void Print_Hex_Dump(const char *title, const uint8_t *data, 
                    uint16_t len, FILE *fp);

/**
 * @brief Performance runners for individual attack scenarios (AS-1/2/4/5/6)
 */
void ccsds_set_run_iterations(uint32_t iterations);
uint32_t ccsds_get_run_iterations(void);
void ccsds_set_run_delay_ms(uint32_t delay_ms);
uint32_t ccsds_get_run_delay_ms(void);
void ccsds_delay_ms(uint32_t delay_ms);
void ccsds_run_as1(void);
void ccsds_run_as2(void);
void ccsds_run_as3(void);
void ccsds_run_as4(void);
void ccsds_run_as5(void);
void ccsds_run_as6(void);
void ccsds_reset_as6_state(void);

#ifdef __cplusplus
}
#endif

#endif /* CCSDS_PACKET_CHECK_H */
