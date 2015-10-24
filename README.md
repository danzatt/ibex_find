Identifies common functions in iBSS/iBEC/iBoot/LLB. Wrapper around ibex by @xerub and Cyanide. Plus IDA Pro plugin.  

Licensed under GPL.

#IDA Pro support
This repositary includes IDA Pro plugin as well. To export locations found by ibex_find for IDA plugin use `-ida` option (`ibex_find ibec.dec.bin -ida > import_me_in_ida_plugin.txt`).
After loading the ida plugin it will rename the adresses to names according to the exported file. In addition to that it will track xrefs to panic functions (and similar) which leak function
names in strings and rename them as well. Using this method I was able to automatically rename ~230 functions for iOS 7 iBoot/iBEC.  
(iOS 9 iBxxx contains far less strings so this method wouldn't be viable.)

#Building
`cc -m32 main.c -D TARGET_BASEADDR=0x5ff00000 -o ibex_find`  
or if you want symbols found by Cyanide as well  
`cc -m32 main.c -D TARGET_BASEADDR=0x5ff00000 -D USE_CYANIDE -o ibex_find`


#Output
```
TARGET_BASEADDR 0x5ff00000
IBOOT_LEN 0x45024
end 0x5ff45024
find_printf() = 0x5ff33ca5
find_snprintf() = 0x5ff3425d
find_malloc() = 0x5ff185cd
find_free() = 0x5ff18681
find_memmove() = 0x5ff34734
find_jumpto() = 0x5ff1e5ed
find_aes_crypto_cmd() = 0x5ff208a5
find_enter_critical_section() = 0x5ff1e9d1
find_exit_critical_section() = 0x5ff1ea3d
find_h2fmi_select() = 0x0
find_create_envvar() = 0x5ff16ef1
find_fs_mount() = 0x5ff22f69
find_fs_loadfile() = 0x5ff231b5
find_bdev_stack() = 0x5ff47208
find_image_list() = 0x5ff44330
```  
Have fun :)
