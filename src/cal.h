#ifndef __CAL_H__
#define __CAL_H__

#include <mtd/mtd-user.h>
#include <mtd/mtd-abi.h>

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


#define CAL_HEADER_LEN sizeof(struct conf_block_header)
/* Magic sequence indicating block header start */
#define CAL_BLOCK_HEADER_MAGIC "ConF"
/* The only known CAL header version. */
#define CAL_HEADER_VERSION 2

struct cal_eraseblock_map
{
  uint32_t to;
  uint32_t from;
};

struct cal_config
{
  char* name;
  struct cal_eraseblock_map *map;
  uint32_t blkcnt;
  uint32_t valid;
  uint32_t first_empty;
  uint32_t write_once;
};

struct cal
{
  int mtd_fd;
  int field_4;
  struct mtd_info_user mtd_info;
  uint32_t blocksize;
  uint32_t erasesize;
  struct conf_block *main_block_list;
  struct conf_block *user_block_list;
  struct conf_block *wp_block_list;
  struct cal_config config[2];
  uint32_t config_in_use;
  struct cal_config config_user;
  struct cal_config config_wp;
  uint32_t user_selectable;
  int field_A4;
  int field_A8;
};

struct conf_block_header {
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
struct conf_block {
  /* Header on-disk offset */
  off_t addr;
  /* Block header. */
  struct conf_block_header hdr;
  /* Block data. */
  void *data;
  /* Pointer to next block (NULL if this block is last). */
  struct conf_block *next;
};



#endif /* __CAL_H__ */
