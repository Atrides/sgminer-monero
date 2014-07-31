#ifndef __DEVICE_GPU_H__
#define __DEVICE_GPU_H__

#include "miner.h"


extern void print_ndevs(int *ndevs);
extern void *reinit_gpu(void *userdata);
extern char *set_gpu_map(char *arg);
extern char *set_gpu_threads(char *arg);
extern char *set_gpu_engine(char *arg);
extern char *set_gpu_fan(char *arg);
extern char *set_gpu_memclock(char *arg);
extern char *set_gpu_memdiff(char *arg);
extern char *set_gpu_powertune(char *arg);
extern char *set_gpu_vddc(char *arg);
extern char *set_temp_overheat(char *arg);
extern char *set_temp_target(char *arg);
extern char *set_intensity(char *arg);
extern char *set_xintensity(char *arg);
extern char *set_rawintensity(char *arg);
extern char *set_vector(char *arg);
extern char *set_worksize(char *arg);
extern char *set_shaders(char *arg);
extern char *set_lookup_gap(char *arg);
extern char *set_thread_concurrency(char *arg);
extern void set_cryptonight_kernel();
void manage_gpu(void);
extern void pause_dynamic_threads(int gpu);

extern int opt_platform_id;

extern struct device_drv opencl_drv;

#endif /* __DEVICE_GPU_H__ */
