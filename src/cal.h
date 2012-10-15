#ifndef __CAL_H__
#define __CAL_H__

#include <mtd/mtd-user.h>
#include <mtd/mtd-abi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CAL_MAX_NAME_LEN	16
#define CAL_FLAG_USER		0x0001
#define CAL_FLAG_WRITE_ONCE	0x0002

#define CAL_FALSE 0
#define CAL_TRUE  1
#define CAL_OK 0
#define CAL_ERROR -1
#define CAL_ERROR_NOT_FOUND -2

#define CAL_BLOCK_FLAG_USER             0x0001
#define CAL_BLOCK_FLAG_VARIABLE_LENGTH  0x0002
#define CAL_BLOCK_FLAG_WRITE_ONCE       0x0004


#define CAL_HEADER_LEN sizeof(struct cal_block_header)
/* Magic sequence indicating block header start */
#define CAL_BLOCK_HEADER_MAGIC "ConF"
/* The only known CAL header version. */
#define CAL_HEADER_VERSION 2

/*
  Structure used to connect offset in CAL area to
  absolute offset in NAND
*/
struct cal_eraseblock_map
{
  uint32_t relative; /* to */
  uint32_t absolute; /* from */
};

/* Description of CAL area */
struct cal_config
{
  char* name;
  struct cal_eraseblock_map *map;
  uint32_t blkcnt;
  uint32_t valid;
  uint32_t first_empty;
  uint32_t write_once;
};

struct cal_block_header {
  /* Magic header. Set to CAL_BLOCK_HEADER_MAGIC. */
  char magic[4];
  /* Header version. Set to CAL_HEADER_VERSION. */
  uint8_t hdr_version;
  /*
          Block version. If there are multiple blocks with same name,
          only block with highest version number is considered active.
          Block version starts with 0.
  */
  uint8_t block_version;
  /*
          Some mysterious flags.
          Possible values: 0, CAL_BLOCK_FLAG_VARIABLE_LENGTH, 1 << 3
  */
  uint16_t flags;
  /* Block name. */
  char name[CAL_MAX_NAME_LEN];
  /* Data length. */
  uint32_t len;
  /* CRC32 for block data. */
  uint32_t data_crc;
  /* CRC32 for header data. */
  uint32_t hdr_crc;
};


/** Structure describing CAL block. */
struct cal_block {
  /* Header on-disk offset */
  off_t addr;
  /* Block header. */
  struct cal_block_header hdr;
  /* Block data. */
  void *data;
  /* Pointer to next block (NULL if this block is last). */
  struct cal_block *next;
};

struct cal
{
  int mtd_fd;
  uint32_t rfu1;
  struct mtd_info_user mtd_info;
  uint32_t blocksize;
  uint32_t erasesize;
  struct cal_block *main_block_list;
  struct cal_block *user_block_list;
  struct cal_block *wp_block_list;
  struct cal_config config[2];
  uint32_t config_in_use;
  struct cal_config config_user;
  struct cal_config config_wp;
  uint32_t user_selectable;
  uint32_t rfu2;
  uint32_t rfu3;
};

extern void (* cal_debug_log)(int level, const char *str);
extern void (* cal_error_log)(const char *str);

int  cal_init(struct cal** cal_out);
void cal_finish(struct cal* cal);

int  cal_read_block(struct cal*    cal,
                    const char*    name,
                    void**         ptr,
                    unsigned long* len,
                    unsigned long  flags);
int  cal_write_block(struct cal*   cal,
                     const char*   name,
                     const void*   data,
                     unsigned long data_len,
                     unsigned long flags);

int  cal_lock_otp_area(struct cal* cal, unsigned int flag);

#ifdef __cplusplus
}
#endif

#endif /* __CAL_H__ */
