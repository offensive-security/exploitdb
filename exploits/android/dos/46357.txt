The following bug report solely looks at the situation on the upstream master
branch; while from a cursory look, at least the wahoo kernel also looks
affected, I have only properly tested this on upstream master.

There is a race condition between the direct reclaim path (enters binder through
the binder_shrinker) and the munmap() syscall (enters binder through the ->close
handler of binder_vm_ops).

Coming from the munmap() syscall:

binder_vma_close()->binder_alloc_vma_close()->binder_alloc_set_vma() sets
alloc->vma to NULL without taking any extra locks; binder_vma_close() is called
from remove_vma()<-remove_vma_list()<-__do_munmap()<-__vm_munmap()<-sys_munmap()
with only the mmap_sem held for writing.

Coming through the direct reclaim path:

binder_alloc_free_page() doesn't hold the mmap_sem on entry. It contains the
following code (comments added by me):

enum lru_status binder_alloc_free_page(struct list_head *item,
                                       struct list_lru_one *lru,
                                       spinlock_t *lock,
                                       void *cb_arg)
{
[...]
        alloc = page->alloc;
        if (!mutex_trylock(&alloc->mutex))
                goto err_get_alloc_mutex_failed;

        if (!page->page_ptr)
                goto err_page_already_freed;

        index = page - alloc->pages;
        page_addr = (uintptr_t)alloc->buffer + index * PAGE_SIZE;
        // unprotected pointer read! `vma` can immediately be freed
        vma = binder_alloc_get_vma(alloc);
        if (vma) {
                if (!mmget_not_zero(alloc->vma_vm_mm))
                        goto err_mmget;
                mm = alloc->vma_vm_mm;
                if (!down_write_trylock(&mm->mmap_sem))
                        goto err_down_write_mmap_sem_failed;
                // mmap_sem is held at this point, but the vma pointer was read
                // before and can be dangling
        }

        list_lru_isolate(lru, item);
        spin_unlock(lock);

        if (vma) {
                trace_binder_unmap_user_start(alloc, index);

                // dangling vma pointer passed to zap_page_range
                zap_page_range(vma,
                               page_addr + alloc->user_buffer_offset,
                               PAGE_SIZE);

                trace_binder_unmap_user_end(alloc, index);

                up_write(&mm->mmap_sem);
                mmput(mm);
        }


Repro instructions:

Unpack the attached binder_race_freevma.tar.
Apply the patch 0001-binder-VMA-unprotected-read-helper.patch to an upstream
git master tree to widen the race window.
Make sure that KASAN is enabled in your kernel config.
Build and boot into the built kernel.
Run "echo 16383 > /sys/module/binder/parameters/debug_mask" for more dmesg debug
output.
Compile the PoC with ./compile.sh and, as root, run ./poc to trigger the bug.

The output of the PoC should look like this:
======================
# ./poc
### PING
0000: 00 . 00 . 00 . 00 .
BR_NOOP:
BR_TRANSACTION:
  target 0000000000000000  cookie 0000000000000000  code 00000001  flags 00000010
  pid     1266  uid        0  data 4  offs 0
0000: 00 . 00 . 00 . 00 .
got transaction!
binder_send_reply(status=0)
offsets=0x7fffb76cf6c0, offsets_size=0
BR_NOOP:
BR_TRANSACTION_COMPLETE:
BR_REPLY:
  target 0000000000000000  cookie 0000000000000000  code 00000000  flags 00000000
  pid        0  uid        0  data 4  offs 0
0000: 00 . 00 . 00 . 00 .
### FLUSHING PAGES
BR_NOOP:
BR_TRANSACTION_COMPLETE:
### END OF PAGE FLUSH
binder_done: freeing buffer
binder_done: free done
### PING DONE
### FLUSHING PAGES
$$$ sleeping before munmap...
$$$ calling munmap now...
$$$ munmap done
### END OF PAGE FLUSH
Killed
======================

The dmesg splat should look like this:
======================
[  803.130180] binder: binder_open: 1265:1265
[  803.132143] binder: binder_mmap: 1265 7fdcbc599000-7fdcbc999000 (4096 K) vma 71 pagep 8000000000000025
[  803.135861] binder: 1265:1265 node 1 u0000000000000000 c0000000000000000 created
[  803.138748] binder: 1265:1265 write 4 at 00007fffb76cf820, read 0 at 0000000000000000
[  803.141875] binder: 1265:1265 BC_ENTER_LOOPER
[  803.143634] binder: 1265:1265 wrote 4 of 4, read return 0 of 0
[  803.146073] binder: 1265:1265 write 0 at 0000000000000000, read 128 at 00007fffb76cf820
[  804.130600] binder: binder_open: 1266:1266
[  804.132909] binder: binder_mmap: 1266 7fdcbc599000-7fdcbc999000 (4096 K) vma 71 pagep 8000000000000025
[  804.138535] binder: 1266:1266 write 68 at 00007fffb76cf850, read 128 at 00007fffb76cf7d0
[  804.142411] binder: 1266:1266 BC_TRANSACTION 2 -> 1265 - node 1, data 00007fffb76cf9a0-00007fffb76cf980 size 4-0-0
[  804.146208] binder: 1265:1265 BR_TRANSACTION 2 1266:1266, cmd -2143260158 size 4-0 ptr 00007fdcbc599000-00007fdcbc599008
[  804.152836] binder: 1265:1265 wrote 0 of 0, read return 72 of 128
[  804.156944] binder: 1265:1265 write 88 at 00007fffb76cf5a0, read 0 at 0000000000000000
[  804.159315] binder: 1265:1265 BC_FREE_BUFFER u00007fdcbc599000 found buffer 2 for active transaction
[  804.161715] binder: 1265 buffer release 2, size 4-0, failed at 000000003c152ea0
[  804.164114] binder: 1265:1265 BC_REPLY 3 -> 1266:1266, data 00007fffb76cf6e0-00007fffb76cf6c0 size 4-0-0
[  804.166646] binder: 1265:1265 wrote 88 of 88, read return 0 of 0
[  804.166756] binder: 1266:1266 BR_TRANSACTION_COMPLETE
[  804.168323] binder: 1265:1265 write 0 at 0000000000000000, read 128 at 00007fffb76cf820
[  804.169876] binder: 1266:1266 BR_REPLY 3 0:0, cmd -2143260157 size 4-0 ptr 00007fdcbc599000-00007fdcbc599008
[  804.171919] binder: 1265:1265 BR_TRANSACTION_COMPLETE
[  804.174743] binder: 1266:1266 wrote 68 of 68, read return 76 of 128
[  804.176003] binder: 1265:1265 wrote 0 of 0, read return 8 of 128
[  804.179416] binder: 1265:1265 write 0 at 0000000000000000, read 128 at 00007fffb76cf820
[  804.179755] binder_alloc: binder_alloc_free_page() starting delay for alloc=000000005f5225f3
[  804.680227] binder_alloc: binder_alloc_free_page() ending delay for alloc=000000005f5225f3
[  804.735851] poc (1266): drop_caches: 2
[  804.772381] binder: 1266:1266 write 12 at 00007fffb76cf8d4, read 0 at 0000000000000000
[  804.774629] binder: 1266:1266 BC_FREE_BUFFER u00007fdcbc599000 found buffer 3 for finished transaction
[  804.791063] binder: 1266 buffer release 3, size 4-0, failed at 000000003c152ea0
[  804.792753] binder: 1266:1266 wrote 12 of 12, read return 0 of 0
[  804.833806] binder_alloc: binder_alloc_free_page() starting delay for alloc=0000000083fec45f
[  805.034060] binder: 1266 close vm area 7fdcbc599000-7fdcbc999000 (4096 K) vma 18020051 pagep 8000000000000025
[  805.041265] binder_alloc: starting binder_alloc_vma_close() for alloc=0000000083fec45f
[  805.045625] binder_alloc: ending binder_alloc_vma_close() for alloc=0000000083fec45f
[  805.331890] binder_alloc: binder_alloc_free_page() ending delay for alloc=0000000083fec45f
[  805.333845] ==================================================================
[  805.338188] BUG: KASAN: use-after-free in zap_page_range+0x7c/0x270
[  805.342064] Read of size 8 at addr ffff8881cd86ba80 by task poc/1266

[  805.346390] CPU: 0 PID: 1266 Comm: poc Not tainted 4.20.0-rc3+ #222
[  805.348277] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.10.2-1 04/01/2014
[  805.350777] Call Trace:
[  805.351528]  dump_stack+0x71/0xab
[  805.352536]  print_address_description+0x6a/0x270
[  805.353947]  kasan_report+0x260/0x380
[...]
[  805.356241]  zap_page_range+0x7c/0x270
[...]
[  805.363990]  binder_alloc_free_page+0x41a/0x560
[...]
[  805.369678]  __list_lru_walk_one.isra.12+0x8c/0x1c0
[...]
[  805.373458]  list_lru_walk_one+0x42/0x60
[  805.374666]  binder_shrink_scan+0xe2/0x130
[...]
[  805.378626]  shrink_slab.constprop.89+0x252/0x530
[...]
[  805.383716]  drop_slab+0x3b/0x70
[  805.384721]  drop_caches_sysctl_handler+0x4d/0xc0
[  805.386150]  proc_sys_call_handler+0x162/0x180
[...]
[  805.392156]  __vfs_write+0xc4/0x370
[...]
[  805.399347]  vfs_write+0xe7/0x230
[  805.400355]  ksys_write+0xa1/0x120
[...]
[  805.403501]  do_syscall_64+0x73/0x160
[  805.404488]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
[...]

[  805.424394] Allocated by task 1266:
[  805.425372]  kasan_kmalloc+0xa0/0xd0
[  805.426264]  kmem_cache_alloc+0xdc/0x1e0
[  805.427349]  vm_area_alloc+0x1b/0x80
[  805.428398]  mmap_region+0x4db/0xa60
[  805.429708]  do_mmap+0x44d/0x6f0
[  805.430564]  vm_mmap_pgoff+0x163/0x1b0
[  805.431664]  ksys_mmap_pgoff+0x2cf/0x330
[  805.432791]  do_syscall_64+0x73/0x160
[  805.433839]  entry_SYSCALL_64_after_hwframe+0x44/0xa9

[  805.435754] Freed by task 1267:
[  805.436527]  __kasan_slab_free+0x130/0x180
[  805.437650]  kmem_cache_free+0x73/0x1c0
[  805.438812]  remove_vma+0x8d/0xa0
[  805.439792]  __do_munmap+0x443/0x690
[  805.440871]  __vm_munmap+0xbf/0x130
[  805.441882]  __x64_sys_munmap+0x3c/0x50
[  805.442926]  do_syscall_64+0x73/0x160
[  805.443951]  entry_SYSCALL_64_after_hwframe+0x44/0xa9

[  805.445926] The buggy address belongs to the object at ffff8881cd86ba40
                which belongs to the cache vm_area_struct of size 200
[  805.449363] The buggy address is located 64 bytes inside of
                200-byte region [ffff8881cd86ba40, ffff8881cd86bb08)
[...]
[  805.475924] ==================================================================
[  805.477921] Disabling lock debugging due to kernel taint
[  805.479843] poc (1266): drop_caches: 2
[  810.482080] binder: 1265 close vm area 7fdcbc599000-7fdcbc999000 (4096 K) vma 18020051 pagep 8000000000000025
[  810.482406] binder: binder_flush: 1266 woke 0 threads
[  810.488231] binder_alloc: starting binder_alloc_vma_close() for alloc=000000005f5225f3
[  810.490091] binder: binder_deferred_release: 1266 threads 1, nodes 0 (ref 0), refs 0, active transactions 0
[  810.493418] binder_alloc: ending binder_alloc_vma_close() for alloc=000000005f5225f3
[  810.498145] binder: binder_flush: 1265 woke 0 threads
[  810.499442] binder: binder_deferred_release: 1265 context_mgr_node gone
[  810.501178] binder: binder_deferred_release: 1265 threads 1, nodes 1 (ref 0), refs 0, active transactions 0
======================


Proof of Concept:
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/46357.zip