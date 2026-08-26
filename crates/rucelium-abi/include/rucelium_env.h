/*
 * rucelium_env.h — RuCelium spore-node wire contract, version 1
 * (ADR-264 §11). This header is the C side of the C ↔ Rust boundary.
 *
 * Contract (ADR-096 posture):
 *   - C owns hardware interaction, fixed-point calibration, deterministic
 *     DSP, serialization, and transport. Nothing else.
 *   - The on-wire encoding is this struct, PACKED, LITTLE-ENDIAN, exactly
 *     RV_ENV_SAMPLE_V1_WIRE_LEN (48) bytes. The Rust gateway parses it with
 *     bounds-checked reads and validates every field before any conversion
 *     into the domain model. Unknown versions / modalities are rejected,
 *     never guessed.
 *   - Sign the 48 wire bytes with the device ed25519 key; transmit the
 *     COSE-inspired envelope [payload, pubkey, signature] as deterministic
 *     CBOR (see rucelium-abi::cbor).
 */

#ifndef RUCELIUM_ENV_H
#define RUCELIUM_ENV_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wire schema version carried in rv_env_sample_v1.schema_version. */
#define RV_ENV_SCHEMA_V1 1u

/* Exact serialized size in bytes (packed, little-endian). */
#define RV_ENV_SAMPLE_V1_WIRE_LEN 48u

/* flags bit 0: this sample is a ring-buffer retransmit after an outage
 * (store-and-forward), so the gateway can distinguish recovery replay from a
 * replay ATTACK — the sequence window still deduplicates either way. */
#define RV_ENV_FLAG_RETRANSMIT (1u << 0)

/* Sensor modality codes (must match rucelium_core::SensorModality). */
enum rv_sensor_type {
    RV_SENSOR_WIFI_CSI = 0,   /* RuView RF context (supporting evidence)   */
    RV_SENSOR_AIR_QUALITY = 1,   /* CO2 / VOC / PM1 / PM2.5 / PM10        */
    RV_SENSOR_SOIL_MOISTURE = 2, /* soil moisture + conductivity          */
    RV_SENSOR_WATER_QUALITY = 3, /* water level / flow / quality          */
    RV_SENSOR_ACOUSTIC = 4,      /* acoustic biodiversity                 */
    RV_SENSOR_WEATHER = 5,       /* temp / humidity / leaf wetness / rain */
    RV_SENSOR_BIOELECTRIC = 6,   /* mycelial bioelectric potential        */
    RV_SENSOR_RADIATION = 7,     /* ionizing radiation                    */
    RV_SENSOR_OPTICAL = 8,       /* light / UV / IR                       */
    RV_SENSOR_CHEMICAL = 9       /* chemical concentration probes         */
};

/*
 * One environmental sample. Q-format fixed point keeps spore nodes
 * float-free: value_q16 is Q16.16, quality_q15 is Q0.15 where
 * 0x8000 == 1.0. Coordinates are degrees x 1e7; altitude is millimetres.
 *
 * NOTE ON PACKING: without packing, natural C alignment would insert 4 bytes
 * of padding before node_id (sizeof == 56). The wire format is the PACKED
 * 48-byte layout. Serialize field-by-field on compilers without
 * __attribute__((packed)).
 */
#if defined(__GNUC__) || defined(__clang__)
typedef struct __attribute__((packed)) {
#else
#pragma pack(push, 1)
typedef struct {
#endif
    uint8_t  schema_version;  /* == RV_ENV_SCHEMA_V1                       */
    uint8_t  sensor_type;     /* enum rv_sensor_type                       */
    uint16_t flags;           /* RV_ENV_FLAG_*                             */
    uint64_t node_id;         /* device identity                           */
    uint64_t timestamp_ns;    /* measurement time, ns since Unix epoch     */
    uint32_t sequence;        /* per-device monotonic sequence number      */
    int32_t  latitude_e7;     /* degrees x 1e7, |lat| <= 900000000         */
    int32_t  longitude_e7;    /* degrees x 1e7, |lon| <= 1800000000        */
    int32_t  altitude_mm;     /* millimetres above reference ellipsoid     */
    int32_t  value_q16;       /* measurement, Q16.16                       */
    uint16_t quality_q15;     /* quality, Q0.15 (0x0000..0x8000)           */
    uint16_t battery_mv;      /* battery level, millivolts                 */
    uint32_t calibration_id;  /* applied calibration record (0 = none)     */
} rv_env_sample_v1;
#if !defined(__GNUC__) && !defined(__clang__)
#pragma pack(pop)
#endif

#if defined(__GNUC__) || defined(__clang__)
_Static_assert(sizeof(rv_env_sample_v1) == RV_ENV_SAMPLE_V1_WIRE_LEN,
               "rv_env_sample_v1 must serialize to exactly 48 bytes");
#endif

#ifdef __cplusplus
}
#endif

#endif /* RUCELIUM_ENV_H */
