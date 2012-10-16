#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <semaphore.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "cal.h"

static void
cal_error_(const char *s)
{
  fprintf(stderr, "CAL ERROR: %s\n", s);
}


#ifdef DEBUG

static void
cal_debug_(int level,const char *s)
{
  fprintf(stderr, "CAL DEBUG: %s\n", s);
}
void (* cal_debug_log)(int level, const char *str) = cal_debug_;

#else

void (* cal_debug_log)(int level, const char *str) = 0;

#endif

void (* cal_error_log)(const char *str) = cal_error_;

void
cal_error(const char *format, ...)
{
  char s[1024];
  va_list va;

  va_start(va, format);

  if ( cal_error_log )
  {
    vsnprintf(s,sizeof(s), format, va);
    s[sizeof(s)-1] = 0;
    cal_error_log(s);
  }
}

void
cal_debug(uint32_t level,const char *format, ...)
{
  char s[1024];
  va_list va;

  va_start(va, format);

  if ( cal_debug_log )
  {
    vsnprintf(s,sizeof(s), format, va);
    s[sizeof(s)-1] = 0;
    cal_debug_log(level,s);
  }
}

static char
header_name_buf[CAL_MAX_NAME_LEN+1];

static const char *
header_name(struct cal_block_header *block_hdr)
{
  strncpy(header_name_buf, block_hdr->name, CAL_MAX_NAME_LEN);
  header_name_buf[CAL_MAX_NAME_LEN] = 0;
  return header_name_buf;
}

static const uint32_t
crc32_tab[] = {
  0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,
  0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,
  0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,
  0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
  0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,
  0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
  0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,
  0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
  0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,
  0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
  0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,
  0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
  0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,
  0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,
  0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,
  0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
  0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,
  0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
  0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,
  0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
  0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,0xF00F9344,0x8708A3D2,0x1E01F268,
  0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,
  0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,
  0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
  0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,
  0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,
  0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,
  0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
  0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,
  0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
  0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,
  0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
  0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,
  0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,
  0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,
  0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
  0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D
};

static uint32_t
calculate_crc32( const uint8_t *buf, size_t size)
{
  if(size)
  {
    size_t i = 0;
    uint32_t crc = 0;

    for(i=0;i<size;i++)
      crc = crc32_tab[(uint8_t)(crc ^ buf[i])] ^ (crc >> 8);

    return crc ;
  }
  return 0;
}

static int
cal_nand_is_bad_eraseblock(int fd, loff_t off)
{
  int rv;
  if ( (rv = ioctl(fd, MEMGETBADBLOCK, &off)) < 0 )
  {
    perror("MEMGETBADBLOCK");
    return CAL_ERROR;
  }
  return rv;
}

static int
map_erase_blocks(struct cal *c,struct  cal_config *conf, uint32_t blkcnt, loff_t *off)
{
  loff_t absolute;
  loff_t relative;
  uint32_t i;

  absolute = *off;
  conf->blkcnt = blkcnt;

  if ( !blkcnt )
  {
    *off = absolute;
    return CAL_OK;
  }

  blkcnt--;
  relative = 0;
  i = 0;

  while ( 1 )
  {
    if ( conf->write_once )
    {
map_it:
      cal_debug(2, "erase block at 0x%016llx mapping to %s 0x%016llx", absolute, conf->name, relative);
      conf->map[i].relative = relative;
      conf->map[i].absolute = absolute;
      relative += c->erasesize;
      i++;
    }
    else
    {
      int is_bad_blk = cal_nand_is_bad_eraseblock(c->mtd_fd, absolute);

      if ( is_bad_blk  < 0 )
        return CAL_ERROR;

      if ( !is_bad_blk )
        goto map_it;

      cal_debug(2, "bad erase block at 0x%16llx", absolute);
      blkcnt++;
    }

    absolute += c->erasesize;
    if ( !blkcnt )
    {
      *off = absolute;
      return CAL_OK;
    }
    blkcnt--;
  }
}

static int
scan_erase_blocks(struct cal *c,unsigned int blkcnt)
{
  loff_t off;

  c->config[0].map =
  c->config[1].map =
  c->config_user.map =
  c->config_wp.map = 0;

  if( !(c->config[0].map = (struct cal_eraseblock_map *)malloc(sizeof(struct cal_eraseblock_map) * blkcnt)) )
    goto err_malloc;

  if ( !(c->config[1].map = (struct cal_eraseblock_map *)malloc(sizeof(struct cal_eraseblock_map) * blkcnt)) )
    goto err_malloc;

  if ( !(c->config_user.map = (struct cal_eraseblock_map *)malloc(sizeof(struct cal_eraseblock_map) * blkcnt)) )
    goto err_malloc;

  if ( c->user_selectable )
  {
    if( !(c->config_wp.map = (struct cal_eraseblock_map *)malloc(sizeof(struct cal_eraseblock_map))) )
      goto err_malloc;
    c->config_wp.write_once = 1;
  }

  off = 0;
  if ( (map_erase_blocks(c, &c->config[0], blkcnt, &off) < 0) ||
       (map_erase_blocks(c, &c->config[1], blkcnt, &off) < 0) ||
       (map_erase_blocks(c, &c->config_user, blkcnt, &off) < 0) )
    goto err;

  if( c->user_selectable )
  {
    off = 0;
    if( map_erase_blocks(c, &c->config_wp, 1, &off) < 0 )
      goto err;
  }

  return 0;

err_malloc:
  cal_error("scan_erase_blocks: malloc");
err:
  if( c->config[0].map )
    free(c->config[0].map);
  if( c->config[1].map )
    free(c->config[1].map);
  if( c->config_user.map )
    free(c->config_user.map);
  if( c->config_wp.map )
    free(c->config_wp.map);
  return CAL_ERROR;
}

int
cal_nand_scan_ebs(struct cal *c)
{
  uint32_t i = 0;
  uint32_t blkcnt = 0;
  uint32_t eraseblocks;

  loff_t off = 0;

  eraseblocks = c->mtd_info.size / c->erasesize;
  off = 0LL;
  if ( !eraseblocks )
    goto err;

  blkcnt = 0;

  do
  {
    int is_bad_eb = cal_nand_is_bad_eraseblock(c->mtd_fd, off);

    if ( is_bad_eb < 0 )
      return CAL_ERROR;

    blkcnt += (is_bad_eb?0:1);
    off += c->erasesize;
    i++;
  }
  while ( eraseblocks != i );

  blkcnt /= 3;

  if ( !blkcnt )
    goto err;

  return scan_erase_blocks(c,blkcnt);

err:
  cal_error("need at least three good erase blocks");
  return CAL_ERROR;
}

int
cal_nand_init(struct cal *c)
{
  int rv = 0;
  uint32_t select_type;

  if ( (c->mtd_fd = open("/dev/mtd1", O_RDWR)) < 0 )
  {
    cal_error("open(%s): %s", "/dev/mtd1", strerror(errno));
    return -1;
  }

  rv = ioctl(c->mtd_fd, MEMGETINFO, &c->mtd_info);

  if ( rv < 0 )
  {
    cal_error("MEMGETINFO: %s", strerror(errno));
    goto err;
  }

  if ( c->mtd_info.type != MTD_NANDFLASH )
  {
    cal_error("Only NAND devices supported");
    goto err;
  }

  c->erasesize = c->mtd_info.erasesize;
  c->blocksize = (c->erasesize < 16385 ? 512 : 2048);

  select_type = MTD_OTP_USER;

  if ( ioctl(c->mtd_fd, OTPSELECT, &select_type) < 0 )
  {
    c->user_selectable = CAL_FALSE;
  }
  else
  {
    c->user_selectable = CAL_TRUE;
    select_type = MTD_OTP_OFF;
    ioctl(c->mtd_fd, OTPSELECT, &select_type);
  }

  return rv;

err:
  close(c->mtd_fd);
  return rv;
}

static void
onen_set_otp_mode(int fd, uint32_t mode)
{
  int select_mode  = (mode >= 1 ? MTD_OTP_USER : MTD_OTP_OFF);

  if ( ioctl(fd, OTPSELECT, &select_mode) < 0 )
    cal_error("onen_set_otp_mode: ioctl OTPSELECT");
}

int
cal_nand_lock_otp_user_region(int fd)
{
  int rv;
  struct otp_info info;

  onen_set_otp_mode(fd, 1);

  info.start = 0;
  info.length = 20480;

  rv = ioctl(fd, OTPLOCK, &info);

  if ( rv < 0 )
  {
    cal_error("OTPLOCK: %s", strerror(errno));
  }

  onen_set_otp_mode(fd, 0);
  return rv;
}

static int
sem_unlock(sem_t *sem)
{
  sem_post(sem);
  return sem_close(sem);
}

static int
sem_lock(sem_t **sem)
{
  int rv = CAL_FALSE;

  *sem = sem_open("nokiacal3", O_CREAT, 0600, 1);

  if ( *sem )
  {
    sem_wait(*sem);
    rv = CAL_TRUE;
  }

  return rv;
}

int
cal_nand_finish(int fd)
{
  return close(fd);
}

static void
free_block_lists(struct cal *c)
{
  struct cal_block *block;
  struct cal_block *next;

  block = c->main_block_list;
  while ( block )
  {
    next = block->next;
    if ( block->data )
      free(block->data);
    free(block);
    block = next;
  }

  block = c->user_block_list;
  while ( block )
  {
    next = block->next;
    if ( block->data )
      free(block->data);
    free(block);
    block = next;
  }

  block = c->wp_block_list;
  while ( block )
  {
    next = block->next;
    if ( block->data )
      free(block->data);
    free(block);
    block = next;
  }

  c->wp_block_list = 0;
  c->user_block_list = 0;
  c->main_block_list = 0;
}

void cal_finish_(struct cal *c)
{
  cal_nand_finish(c->mtd_fd);
  free_block_lists(c);
  free(c->config[0].map);
  free(c->config[1].map);
  free(c->config_user.map);
  free(c->config_wp.map);
  free(c);
}

int cal_lock_otp_area_(int fd, uint32_t select_mode)
{
  if ( select_mode == 2 )
    return cal_nand_lock_otp_user_region(fd);
  else
    return CAL_ERROR;
}

int
cal_nand_erase_area(struct cal *c, struct cal_config *conf)
{
  uint32_t i;

  if ( conf->blkcnt )
  {
    struct cal_eraseblock_map *map = conf->map;
    for ( i=0; i<conf->blkcnt; i++ )
    {
      struct erase_info_user ei;

      cal_debug(1, "erasing block at 0x%08x", map->absolute);

      ei.start = map->absolute;
      ei.length = c->erasesize;

      if ( ioctl(c->mtd_fd, MEMERASE, &ei) < 0 )
      {
        cal_error("MEMERASE 0x%08x: %s", map->absolute, strerror(errno));
        return CAL_ERROR;
        break;
      }
      map++;
    }
  }

  return CAL_OK;
}

static struct cal_block *
find_block(struct cal_block *block, const char *name)
{

  while ( block )
  {
    cal_debug(4, "checking block '%s'", header_name(&block->hdr));

    if ( !strncmp(block->hdr.name, name, CAL_MAX_NAME_LEN) )
      break;

    block = block->next;
  }

  return block;
}

static struct cal_block *
find_block_type(struct cal *c, const char *name, uint16_t type)
{
  struct cal_block *rv;

  if ( type & CAL_FLAG_USER )
  {
    rv = find_block(c->user_block_list, name);
  }
  else
  {
    rv = find_block(c->wp_block_list, name);
    if ( !(type & CAL_FLAG_WRITE_ONCE) )
    {
      if ( !rv )
        rv = find_block(c->main_block_list, name);
    }
  }
  return rv;
}

static int
get_offset(struct cal *c,struct  cal_config *config, off_t addr, off_t *off)
{
  int blkcnt;
  struct cal_eraseblock_map *map;
  int i;
  uint32_t erasesize;

  erasesize = c->mtd_info.erasesize;
  blkcnt = config->blkcnt;
  map = config->map;
  if ( blkcnt )
  {
    i = 0;
    while ( map->relative > addr || addr >= erasesize + map->relative )
    {
      i++;
      if ( i == blkcnt )
        return CAL_ERROR;
      map++;
    }
    *off = map->absolute + addr % erasesize;
    return CAL_OK;
  }

  return CAL_ERROR;
}

int
cal_nand_read(struct cal *c, struct cal_config *config, off_t addr, uint8_t *buf, off_t len)
{
  size_t count;
  uint32_t erasesize;
  off_t off;

  erasesize = c->mtd_info.erasesize;

  if ( c->user_selectable && config->write_once)
    onen_set_otp_mode(c->mtd_fd, 1);

  cal_debug(2, "cal_nand_read: %u bytes from %s addr 0x%08x%s", len, config->name, addr, config->write_once?" OTP":"");

  if ( len )
  {
    while ( 1 )
    {
      if ( erasesize - addr % erasesize <= len )
        count = erasesize - addr % erasesize;
      else
        count = len;

      if ( get_offset(c, config, addr, &off) < 0 )
      {
        cal_error("nand_read: invalid addr: 0x%08x", addr);
        goto err;
      }

      cal_debug(2, "nand_read: %d bytes from 0x%08x", count, off);

      if ( lseek(c->mtd_fd, off, SEEK_SET) < 0 )
      {
        cal_error("nand_read: lseek %08x: %s", off, strerror(errno));
        goto err;
      }

      if ( count != read(c->mtd_fd, buf, count) )
        break;

      len -= count;

      if ( !len )
        goto out;

      buf += count;
      addr += count;
    }
    cal_error("nand_read: read (%d bytes at %08x): %s", count, off, strerror(errno));
    goto err;
  }

out:
    if ( c->user_selectable && config->write_once )
      onen_set_otp_mode(c->mtd_fd, 0);
  return CAL_OK;

err:
  if ( c->user_selectable && config->write_once )
    onen_set_otp_mode(c->mtd_fd, 0);

  return CAL_ERROR;
}


static int
cal_nand_read_block_data(struct cal *c, struct cal_config *config, struct cal_block *block)
{
  void *data;

  if ( block->data )
  {
    cal_debug(0, "block '%s', len %u found from cache",
              header_name(&block->hdr),
              block->hdr.len);
    return CAL_OK;
  }

  cal_debug(0,
            "reading block from %s addr 0x%08x, name '%s', len %u",
            config->name,
            block->addr,
            header_name(&block->hdr),
            block->hdr.len);

  data = malloc(block->hdr.len);

  if ( data )
  {
    if ( cal_nand_read(c, config, block->addr + (int)CAL_HEADER_LEN, data, block->hdr.len) >= 0 )
    {
      uint32_t crc = calculate_crc32(data, block->hdr.len);
      uint32_t hdr_crc = block->hdr.data_crc;

      if ( crc == hdr_crc )
      {
        block->data = data;
        return 0;
      }

      cal_error(
        "data CRC mismatch on conf block at addr 0x%08x, name '%s' (calc %08x vs. %08x)",
        block->addr,
        header_name(&block->hdr),
        crc,
        hdr_crc);
    }
    free(data);
    goto err;
  }

  cal_error("read_block_data: malloc: %s");

err:
  return CAL_ERROR;
}

int
cal_read_block_(struct cal *c, const char *name, void **data_out, unsigned long *data_len, unsigned long type)
{
  struct cal_block *block;
  struct cal_config *config;

  if ( strlen(name) > CAL_MAX_NAME_LEN )
  {
    cal_error("cal_read_block: too long name");
    goto err;
  }

  config = (type & CAL_FLAG_USER)?
        &c->config_user:
        &c->config[c->config_in_use];

  cal_debug(2, "trying to find%s block '%s'", type & CAL_FLAG_USER?" user":"", name);

  block = find_block_type(c, name, type);

  if ( !block )
  {
    cal_debug(1, "block '%s' not found", name);
    return CAL_ERROR_NOT_FOUND;
  }

  if ( (block->hdr.flags & CAL_BLOCK_FLAG_WRITE_ONCE) && c->user_selectable )
    config = &c->config_wp;

  if ( cal_nand_read_block_data(c, config, block) < 0 )
    goto err;

  if ( !(*data_out = malloc(block->hdr.len)) )
  {
    cal_error("cal_read_block: malloc: %s");
    goto err;
  }

  memcpy(*data_out, block->data, block->hdr.len);
  *data_len = block->hdr.len;

  return CAL_OK;

err:
  return CAL_ERROR;
}

static int
check_block_header(struct cal *c, struct cal_config *config, off_t addr, struct cal_block_header *block_header)
{
  uint32_t crc;

  cal_debug(2, "reading %s block header at 0x%08x", config->name, addr);

  if ( cal_nand_read(c, config, addr, (uint8_t*)block_header, CAL_HEADER_LEN) < 0 )
  {
    cal_error("failed to read %d bytes at %s 0x%08x", CAL_HEADER_LEN, config->name, addr);
    return CAL_ERROR;
  }

  if ( memcmp(block_header->magic, CAL_BLOCK_HEADER_MAGIC, 4) )
  {
    uint32_t magic;
    memcpy(&magic,block_header->magic,sizeof(uint32_t));
    if( magic != -1 )
    {
      cal_error("invalid header magic at addr 0x%08x: %08x", addr, magic);
      return CAL_ERROR;
    }
    else
      return CAL_ERROR_NOT_FOUND;
  }

  if ( block_header->hdr_version != CAL_HEADER_VERSION )
  {
    cal_error("invalid header version at addr %08x: %d", addr, block_header->hdr_version);
    return CAL_ERROR;
  }

  if ( (crc = calculate_crc32((uint8_t*)block_header, CAL_HEADER_LEN-sizeof(block_header->hdr_crc))) != block_header->hdr_crc )
  {
    cal_error("header CRC mismatch at addr %08x: calc %08x vs. %08x", addr, crc, block_header->hdr_crc);
    return CAL_ERROR;
  }

  if ( c->erasesize + config->map[config->blkcnt - 1].relative < addr + block_header->len + 4 )
  {
    cal_error("block at addr %08x runs over device size", addr);
    return CAL_ERROR;
  }

  return CAL_OK;
}

static void
insert_block(struct cal *c, struct cal_block *block)
{
  uint8_t current_version;
  uint8_t version;

  struct cal_block **list;

  struct cal_block *next;
  struct cal_block *found;
  struct cal_block *current;

  block->next = 0;

  if ( block->hdr.flags & CAL_BLOCK_FLAG_USER )
    list = &c->user_block_list;
  else if ( block->hdr.flags & CAL_BLOCK_FLAG_WRITE_ONCE )
    list = &c->wp_block_list;
  else
    list = &c->main_block_list;

  if ( !*list )
  {
    *list = block;
    return;
  }

  current = *list;

  found = 0;

  do
  {
    while ( strncmp(current->hdr.name, block->hdr.name, CAL_MAX_NAME_LEN) )
    {
      found = current;
      current = current->next;
      if ( !current )
        goto out;
    }

    current_version = current->hdr.block_version;
    version = block->hdr.block_version;

    if ( current_version <= 0xBEu )
    {
      if (version > 0xBEu && (current_version <= 0x3Fu || current_version > version) )
      {
        cal_error("Aieee! Some serious inconsistency in block versioning");
        goto version_error;
      }
    }

    if ( version > 0x3Fu )
    {
      if (version > 0xBEu && (current_version <= 0x3Fu || current_version > version) )
      {
        cal_error("Aieee! Some serious inconsistency in block versioning");
        goto version_error;
      }
    }

    if ( current_version != version )
    {
version_error:
      if ( found )
        found->next = current->next;
      else
        *list = current->next;
    }

    next = current->next;

    if ( current->data )
      free(current->data);

    free(current);

    current = next;
  }
  while ( next );

out:
  if ( found )
    found->next = block;
  else
    *list = block;
}

static int
scan_block_headers(struct cal *c, struct cal_config *config, uint16_t type)
{
  struct cal_block *block;
  off_t addr;
  uint32_t offset;
  struct cal_block_header block_header;

  offset = c->erasesize + config->map[config->blkcnt - 1].relative;
  addr = 0;

  while ( 1 )
  {
    int rv = check_block_header(c, config, addr, &block_header);

    if ( rv == CAL_ERROR_NOT_FOUND )
    {
      if ( !(addr % c->blocksize) )
        goto out;

      addr = (-c->blocksize) & (c->blocksize + addr - 1);
    }
    else
    {
      if ( rv < 0 )
        break;

      cal_debug(1, "found block '%s' at %s vaddr %08x (ver %d, len %d)",
                header_name(&block_header),
                config->name,
                addr,
                block_header.block_version, block_header.len);

      if ( type & CAL_FLAG_USER )
      {
        if ( !(block_header.flags & CAL_BLOCK_FLAG_USER) )
        {
          cal_error("non-user block '%s' found in a user area", header_name(&block_header));
          break;
        }
        if ( block_header.flags & CAL_BLOCK_FLAG_WRITE_ONCE )
        {
          cal_error("write-once block '%s' found in a user area", header_name(&block_header));
          break;
        }
      }
      else if ( type & CAL_FLAG_WRITE_ONCE )
      {

        if ( !(block_header.flags & CAL_BLOCK_FLAG_WRITE_ONCE) )
        {
          cal_error("non-write-once block '%s' found in WP area", header_name(&block_header));
          break;
        }
      }
      else if ( block_header.flags & CAL_BLOCK_FLAG_USER )
      {
        cal_error("user block '%s' found in a non-user area", header_name(&block_header));
        break;
      }
      else if ( c->user_selectable && (block_header.flags & CAL_BLOCK_FLAG_WRITE_ONCE) )
      {
        cal_error("write-once block '%s' found in a non-WP area", header_name(&block_header));
        break;
      }

      block = (struct cal_block *)malloc(sizeof(struct cal_block));

      if ( !block )
      {
        cal_error("scan_block_headers: malloc");
        break;
      }

      memcpy(&block->hdr, &block_header, sizeof(block->hdr));
      block->addr = addr;
      block->data = 0;
      insert_block(c, block);
      addr += (block->hdr.len + 0x27) & 0xFFFFFFFC;
    }

    if ( offset <= addr + CAL_HEADER_LEN )
      goto out;
  }


  return CAL_ERROR;

out:
  config->first_empty = (-c->blocksize) & (c->blocksize + addr - 1);
  cal_debug(1, "%s empty area starts at 0x%08x", config->name, addr);
  return CAL_OK;

}

int
cal_init_(struct cal **cal_out)
{
  struct cal *c;
  int rv;
  int config;
  struct cal_block_header config1_block_header;
  struct  cal_block_header config2_block_header;

  cal_debug(2, "cal_init() called");

  if ( !(c = (struct cal *)malloc(sizeof(struct cal))) )
  {
    cal_error("malloc");
    return CAL_ERROR;
  }
  memset(c, 0, sizeof(struct cal));

  c->config[0].name = "config1";
  c->config[1].name = "config2";
  c->config_user.name = "user";

  if ( (rv = cal_nand_init(c)) < 0 )
    goto err_out;

  if ( c->user_selectable )
    c->config_wp.name = "wp";

  if ( (rv = cal_nand_scan_ebs(c)) < 0 )
  {
    cal_nand_finish(c->mtd_fd);
    goto err_out;
  }

  if ( !check_block_header(c, c->config, 0, &config1_block_header) )
    c->config[0].valid = 1;

  if ( !check_block_header(c, &c->config[1], 0, &config2_block_header) )
    c->config[1].valid = 1;

  if ( !c->config[0].valid )
  {
    if ( !c->config[1].valid )
    {
      cal_error("both configuration areas are invalid; choosing first half");
      c->config_in_use = 0;
      goto scan_headers;
    }
    cal_debug(0, "first half is bad, choosing second");
    c->config_in_use = 1;
    goto check_header;
  }

  if ( !c->config[1].valid )
  {
    cal_debug(0, "second half is bad, choosing first");
    c->config_in_use = 0;
    goto check_header;
  }

  cal_debug(
    1,
    "both config areas are good; first half version %d, second %d",
    config1_block_header.block_version,
    config2_block_header.block_version);

  if ( config1_block_header.block_version > 0xBEu &&
       config2_block_header.block_version <= 0x3Fu)
  {
    cal_debug(0, "choosing second half");
    c->config_in_use = 1;

  }
  else if ( (config2_block_header.block_version > 0xBEu && config1_block_header.block_version <= 0x3Fu) ||
       (config2_block_header.block_version < config1_block_header.block_version) )
  {
    cal_debug(0, "choosing first half");
    c->config_in_use = 0;
  }
  else
  {
    cal_debug(0, "choosing second half");
    c->config_in_use = 1;
  }

check_header:

  if ( !check_block_header(c, &c->config_user, 0, &config1_block_header) )
  {
    c->config_user.valid = 1;
    cal_debug(0, "user area seems to be ok");

    if ( !c->user_selectable )
      goto scan_headers;

check_wp_header:

    if ( check_block_header(c, &c->config_wp, 0, &config1_block_header) )
    {
      cal_debug(0, "write-once area not valid");
    }
    else
    {
      c->config_wp.valid = 1;
      cal_debug(0, "write-once area seems to be ok");
    }
    goto scan_headers;
  }

  cal_debug(0, "user area not valid");

  if ( c->user_selectable )
    goto check_wp_header;

scan_headers:

  if ( c->config[c->config_in_use].valid )
  {
    cal_debug(1, "scanning %s area", c->config[c->config_in_use].name);
    if ( scan_block_headers(c, &c->config[c->config_in_use], 0) < 0 )
    {
      cal_error("error in primary config block; trying to use spare");
      c->config[c->config_in_use].valid = 0;

      config = (c->config_in_use == 0?1:0);
      c->config_in_use = config;

      free_block_lists(c);

      if ( scan_block_headers(c, &c->config[config], 0) < 0 )
      {
        cal_error("error secondary config block too; now this is messed up");
        c->config[config].valid = 0;
        c->config_in_use = (c->config_in_use == 0?1:0);
        free_block_lists(c);
      }
    }
  }

  if ( c->config_user.valid && (scan_block_headers(c, &c->config_user, 1) < 0) )
  {
    c->config_user.valid = 0;
  }
  if ( c->config_wp.valid )
  {
    if ( scan_block_headers(c, &c->config_wp, 2) < 0 )
      c->config_wp.valid = 0;
  }

  *cal_out = c;
  rv = CAL_OK;
  goto out;

err_out:
  free(c);

out:
  return rv;
}

int
cal_lock_otp_area(struct cal *c, uint32_t flag)
{
  int rv = CAL_ERROR;
  sem_t *sem;

  if ( sem_lock(&sem) )
  {
    if ( cal_init_(&c) == CAL_TRUE)
    {
      rv = cal_lock_otp_area_(c->mtd_fd, flag);
      cal_finish_(c);
    }
    sem_unlock(sem);
  }
  return rv;
}

int  cal_read_block(struct cal*    cal,
                    const char*    name,
                    void**         ptr,
                    unsigned long* len,
                    unsigned long  flags)
{
  int rv=CAL_ERROR;
  sem_t *sem;

  if ( sem_lock(&sem) )
  {
    if ( cal_init_(&cal) >= 0 )
    {
      rv = cal_read_block_(cal, name, ptr, len, flags);
      cal_finish_(cal);
    }
    sem_unlock(sem);
  }

  return rv;
}


static int
verify_write(struct cal *c, const void* data, off_t offset)
{
  uint8_t buf[2048];
  int i;

  if ( lseek(c->mtd_fd, offset, SEEK_SET) < 0 )
  {
    cal_error("verify_write: lseek %08x: %s", offset, strerror(errno));
    return CAL_ERROR;
  }

  if ( c->blocksize != read(c->mtd_fd, buf, c->blocksize) )
  {
    cal_error("verify_write: read (%d bytes at around %08x): %s",
              c->blocksize, offset, strerror(errno));
    return CAL_ERROR;
  }

  for(i=0; i<c->blocksize; i++)
  {
    if(((uint8_t*)data)[i] != buf[i])
      break;
  }
  if (c->blocksize &&  ( i < c->blocksize && ((uint8_t*)data)[i] != buf[i]) )
  {
    cal_error("verify error at paddr 0x%08x: read 0x%02x, want 0x%02x",
              ((uint8_t*)offset)+i,
              buf[i],
              ((uint8_t*)data)[i]);
    return CAL_ERROR;
  }

  return CAL_OK;
}

int cal_nand_write(struct cal *c, struct cal_config *area, off_t addr, const void* data, unsigned int len)
{
  int rv = CAL_OK;
  uint32_t erasesize;
  uint32_t bytes;
  uint32_t i;
  off_t offset;

  erasesize = c->mtd_info.erasesize;

  if ( addr % c->blocksize ||
       len % c->blocksize )
  {
    cal_error("nand_write: both addr and len must be aligned on page boundary (0x%08x, %d)",
              addr,
              len,
              len / c->blocksize);
    return CAL_ERROR;
  }

  if ( c->user_selectable && area->write_once )
    onen_set_otp_mode(c->mtd_fd, 1);

  if ( !len )
    goto out;

  while ( 1 )
  {
    if ( erasesize - addr % erasesize > len )
      bytes = len;
    else
      bytes = erasesize - addr % erasesize;

    if ( get_offset(c, area, addr, &offset) < 0 )
    {
      cal_error("nand_write: invalid addr: 0x%08x", addr);
      goto err;
    }

    cal_debug(2, "nand_write: %d bytes to 0x%08x", bytes, offset);

    if ( bytes / c->blocksize > 0 )
      break;

next:

    len -= bytes;

    if ( !len )
      goto out;

    addr += bytes;
  }

  i = 0;

  while ( 1 )
  {
    if ( lseek(c->mtd_fd, offset, 0) < 0 )
    {
      cal_error("nand_write: lseek %08x: %s", offset, strerror(errno));
      goto err;
    }

    if ( c->blocksize != write(c->mtd_fd, data, c->blocksize) )
    {
      cal_error("nand_write: write (%d bytes at around %08x): %s",
                bytes, offset, strerror(errno));
      goto err;
    }

    if(verify_write(c,data,offset) < 0)
      goto err;

    offset += c->blocksize;
    data += c->blocksize;

    i++;

    if ( i == bytes / c->blocksize )
      goto next;
  }

err:
  rv =  CAL_ERROR;

out:
  if ( c->user_selectable && area->write_once )
    onen_set_otp_mode(c->mtd_fd, 0);

  return rv;
}

static int
store_block(struct cal *c, struct cal_config *conf, struct cal_block * block, uint32_t len, unsigned long flags)
{
  int rv;
  uint8_t* buf = (uint8_t*)malloc(len);
  uint8_t* p = buf;

  if ( !buf )
  {
    cal_error("store_block: malloc buf");
    goto err;
  }

  memcpy(p, &block->hdr, CAL_HEADER_LEN);
  memcpy(p += sizeof(block->hdr), block->data, block->hdr.len);
  memset(p + block->hdr.len, 0xFF, len - block->hdr.len - CAL_HEADER_LEN);

  if ( !conf->valid && (!c->user_selectable || !(flags & CAL_FLAG_WRITE_ONCE)) )
  {
    cal_debug(0, "initializing %s config area", conf->name);
    if ( cal_nand_erase_area(c, conf) < 0 )
    {
      free(buf);
      goto err;
    }
  }

  rv = cal_nand_write(c, conf, conf->first_empty, buf, len);
  free(buf);

  if ( rv < 0 )
  {
err:
    return CAL_ERROR;
  }

  if ( !conf->valid )
    conf->valid = 1;

  block->addr = conf->first_empty;
  insert_block(c, block);
  conf->first_empty += len;
  return CAL_OK;
}

static void
set_header(struct cal_block* block,const char* name,uint8_t version, const void* data, uint32_t len, unsigned long flags)
{
  /* magic */
  memcpy(block->hdr.magic, CAL_BLOCK_HEADER_MAGIC, sizeof(block->hdr.magic));

  /* header version */
  block->hdr.hdr_version = CAL_HEADER_VERSION;

  /* block version */
  block->hdr.block_version = version;

  /* flags */
  block->hdr.flags = 0;
  if ( flags & CAL_FLAG_USER )
    block->hdr.flags = CAL_BLOCK_FLAG_USER;
  if ( flags & CAL_FLAG_WRITE_ONCE )
    block->hdr.flags |= CAL_BLOCK_FLAG_WRITE_ONCE;

  /* name */
  memset(block->hdr.name, 0, sizeof(block->hdr.name));
  strncpy(block->hdr.name, name, CAL_MAX_NAME_LEN);
  memcpy(block->data, data, len);

  /* length */
  block->hdr.len = len;

  /* crc32 */
  block->hdr.data_crc = calculate_crc32((uint8_t*)block->data, len);
  block->hdr.hdr_crc = calculate_crc32((uint8_t*)&block->hdr, CAL_HEADER_LEN-sizeof(block->hdr.hdr_crc));

}

static int
get_config_blocks_size(struct cal* c,struct cal_config* conf,struct cal_block* block, uint32_t* config_blocks_size, unsigned long flags)
{
  *config_blocks_size = 0;

  while ( cal_nand_read_block_data(c, conf, block) >= 0 )
  {
    *config_blocks_size += (block->hdr.len + 0x27) & 0xFFFFFFFC;
    block = block->next;

    if ( !block )
    {
      if ( c->user_selectable || (flags & CAL_FLAG_USER) || !(block = c->wp_block_list) )
        return CAL_OK;
    }
  }
  return CAL_ERROR;
}

int
cal_write_block_(struct cal *c, const char *name, const void *data, unsigned long data_len, unsigned long flags)
{
  uint8_t version;
  uint32_t len_free;

  uint8_t* p;
  uint8_t* next;

  uint8_t* config_area;
  uint32_t config_area_len;
  uint32_t config_area_end;

  uint32_t len;
  uint32_t config_blocks_size;

  struct cal_config *conf;
  struct cal_block *block;


  cal_debug(0, "writing block '%s', data len %d", name, data_len);

  if ( strlen(name) > CAL_MAX_NAME_LEN )
  {
    cal_error("cal_write_block: too long name");
    return CAL_ERROR;
  }

  if ( (flags & CAL_FLAG_WRITE_ONCE) && (flags & CAL_FLAG_USER) )
  {
    cal_error("write-once user blocks not supported");
    return CAL_ERROR;
  }

  block = find_block_type(c, name, flags);

  if ( block )
  {
    if ( flags & CAL_FLAG_WRITE_ONCE )
    {
      cal_error("trying to overwrite write-once block");
      return CAL_ERROR;
    }
    version = block->hdr.block_version + 1;
  }
  else
  {
    version = 0;
  }

  if ( !(block = (struct cal_block *)malloc(sizeof(struct cal_block))) )
  {
    cal_error("cal_write_block: malloc block");
    return CAL_ERROR;
  }

  if ( !(block->data = malloc(data_len)) )
  {
    cal_error("cal_write_block: malloc cache");
    free(block);
    return CAL_ERROR;
  }

  set_header(block, name, version, data, data_len, flags);

  conf = flags & CAL_FLAG_USER? &c->config_user :
                                (flags & CAL_FLAG_WRITE_ONCE) && c->user_selectable ? &c->config_wp :
                                                                                      &c->config[c->config_in_use];

  len_free = c->erasesize + conf->map[conf->blkcnt - 1].relative;
  len = -c->blocksize & (block->hdr.len + c->blocksize + 0x23);

  cal_debug(
    1,
    "trying to write new%s conf block to 0x%08x (%d bytes)",
    flags & CAL_FLAG_USER ? " user" : flags & CAL_FLAG_WRITE_ONCE ? " write-once" :"",
    conf->first_empty, len);

  if ( len_free < len )
  {
    cal_error("block size too big");
    goto err;
  }

  if ( len_free >= conf->first_empty + len )
  {
    if( store_block(c,conf,block,len,flags) < 0 )
      goto err;
    else
      return CAL_OK;
  }

  cal_debug(0, "block doesn't fit into empty space");

  if ( c->user_selectable && (flags & CAL_FLAG_WRITE_ONCE) )
  {
    cal_error("block doesn't fit into write-once region");
    goto err;
  }

  insert_block(c, block);

  block = flags & CAL_FLAG_USER ? c->user_block_list :
                                  c->main_block_list;

  cal_debug(0, "compressing%s config area", flags & CAL_FLAG_USER ? " user" : "");

  if ( block )
  {
    if( get_config_blocks_size(c,conf,block,&config_blocks_size, flags) < 0 )
    {
      cal_error("compress_config_area: invalid block data. aieee!");
      goto err;
    }
  }
  else
    config_blocks_size = 0;

  cal_debug(0, "total size of config blocks %d", config_blocks_size);
  config_area_len = -c->blocksize & (config_blocks_size + c->blocksize - 1);

  if ( config_area_len > c->erasesize * conf->blkcnt )
  {
    cal_error("config blocks won't fit into config area");
    goto err;
  }

  if ( !(config_area = malloc(config_area_len)) )
  {
    cal_error("compress_config_area: malloc");
    goto err;
  }

  if ( block )
  {
    struct cal_block * b = block;
    p = config_area;

try_next:

    if ( !(flags & CAL_FLAG_USER) )
    {
      if(b == block)
        b->hdr.block_version++;

      while ( 1 )
      {
        b->hdr.hdr_crc = calculate_crc32((uint8_t*)&b->hdr, CAL_HEADER_LEN - sizeof(b->hdr.hdr_crc));
        b->addr = p - config_area;

        cal_debug(3, "writing '%s' (version %d) to idx %d",
                  header_name(&b->hdr), b->hdr.block_version, b->addr);

        memcpy(p, &b->hdr, CAL_HEADER_LEN);
        memcpy(p + CAL_HEADER_LEN, b->data, b->hdr.len);

        next = &p[b->hdr.len + CAL_HEADER_LEN];

        p = next;
        config_area_end = next - config_area;

        while(config_area_end & 3)
        {
          *p++ = 0xFF;
          config_area_end++;
        }

        if ( (b = b->next) )
          goto try_next;

        if ( !c->user_selectable && !(flags & CAL_FLAG_USER) && ((b = c->wp_block_list)) )
          continue;

        goto found;
      }
    }
    b->hdr.block_version = 0;
  }
  p = config_area;
  config_area_end = 0;

found:

  memset(p, 0xFF, config_area_len - config_area_end);

  if ( !flags & CAL_FLAG_USER )
    conf = &c->config[c->config_in_use?0:1];

  if ( cal_nand_erase_area(c, conf) < 0
    || cal_nand_write(c, conf, c->blocksize, config_area + c->blocksize, config_area_len - c->blocksize) < 0
    || cal_nand_write(c, conf, 0, config_area, c->blocksize) < 0)
  {
    free(config_area);
    goto err;
  }

  free(config_area);

  if ( !(flags & CAL_FLAG_USER) )
    c->config_in_use = c->config_in_use?0:1;

  conf->first_empty = -c->blocksize & (config_area_len + c->blocksize - 1);
  conf->valid = CAL_TRUE;

  return CAL_OK;

err:
  free(block->data);
  free(block);
  return CAL_ERROR;
}

int  cal_write_block(struct cal*   cal,
                     const char*   name,
                     const void*   data,
                     unsigned long data_len,
                     unsigned long flags)

{
  int rv=CAL_ERROR;
  sem_t *sem;

  if ( sem_lock(&sem) )
  {
    if ( cal_init_(&cal) >= 0 )
    {
      rv = cal_write_block_(cal, name, data, data_len, flags);
      cal_finish_(cal);
    }
    sem_unlock(sem);
  }

  return rv;
}

void
cal_finish(struct cal *c)
{
}

int
cal_init(struct cal **cal_out)
{
  return 0;
}

void main()
{
  struct cal c;
  void* data;
  uint8_t t[]="HELLO fhdsjkfhsdkj";
  unsigned long len;
  unsigned long flags = 0;

  if(cal_read_block(&c,"aivo-ver",&data,&len,flags) == CAL_OK)
  {
    printf("%s\n",(char*)data);
    free(data);
  }

  if(cal_write_block(&c,"aivo-ver",t,sizeof(t),flags) == CAL_OK)
  {
    if(cal_read_block(&c,"aivo-ver",&data,&len,flags) == CAL_OK)
    {
      printf("%s\n",(char*)data);
      free(data);
    }
  }
}
