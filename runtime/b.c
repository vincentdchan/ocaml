#include "binaryen-c.h"
    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/mman.h>

    static void dump_bytes_to_path(void* bytes, size_t len, const char* path) {
      int fd;
      fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
      if (fd < 0) {
        printf("can not open file");
        return;
      }

      ftruncate(fd, len);

      void* src = mmap(NULL, len, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, 0);
      if (src < 0 || src == 0) {
        close(fd);
        printf("map to file failed");
        return;
      }

      memcpy(src, bytes, len);
      munmap(src, len);
      close(fd);
    }

    static void clean_binary_result(BinaryenModuleAllocateAndWriteResult result) {
      if (result.binary) {
        free(result.binary);
      }
      if (result.sourceMap) {
        free(result.sourceMap);
      }
    }
#include "ctypes_cstubs_internals.h"
CAMLprim value binaryen_stub_1_BinaryenModuleCreate(value x1)
{
   void* x2 = BinaryenModuleCreate();
   return CTYPES_FROM_PTR(x2);
}
CAMLprim value binaryen_stub_2_BinaryenModuleDispose(value x3)
{
   void* x4 = CTYPES_ADDR_OF_FATPTR(x3);
   BinaryenModuleDispose(x4);
   return Val_unit;
}
CAMLprim value binaryen_stub_3_BinaryenTypeNone(value x6)
{
   uintptr_t x7 = BinaryenTypeNone();
   return integers_copy_uint64(x7);
}
CAMLprim value binaryen_stub_4_BinaryenTypeInt32(value x8)
{
   uintptr_t x9 = BinaryenTypeInt32();
   return integers_copy_uint64(x9);
}
CAMLprim value binaryen_stub_5_BinaryenTypeInt64(value x10)
{
   uintptr_t x11 = BinaryenTypeInt64();
   return integers_copy_uint64(x11);
}
CAMLprim value binaryen_stub_6_BinaryenTypeFloat32(value x12)
{
   uintptr_t x13 = BinaryenTypeFloat32();
   return integers_copy_uint64(x13);
}
CAMLprim value binaryen_stub_7_BinaryenTypeFloat64(value x14)
{
   uintptr_t x15 = BinaryenTypeFloat64();
   return integers_copy_uint64(x15);
}
CAMLprim value binaryen_stub_8_BinaryenTypeAnyref(value x16)
{
   uintptr_t x17 = BinaryenTypeAnyref();
   return integers_copy_uint64(x17);
}
CAMLprim value binaryen_stub_9_BinaryenTypeUnreachable(value x18)
{
   uintptr_t x19 = BinaryenTypeUnreachable();
   return integers_copy_uint64(x19);
}
CAMLprim value binaryen_stub_10_BinaryenTypeAuto(value x20)
{
   uintptr_t x21 = BinaryenTypeAuto();
   return integers_copy_uint64(x21);
}
CAMLprim value binaryen_stub_11_BinaryenTypeCreate(value x23, value x22)
{
   uintptr_t* x24 = CTYPES_ADDR_OF_FATPTR(x23);
   uint32_t x25 = Uint32_val(x22);
   uintptr_t x28 = BinaryenTypeCreate(x24, x25);
   return integers_copy_uint64(x28);
}
CAMLprim value binaryen_stub_12_BinaryenAddInt32(value x29)
{
   int32_t x30 = BinaryenAddInt32();
   return caml_copy_int32(x30);
}
CAMLprim value binaryen_stub_13_BinaryenSubInt32(value x31)
{
   int32_t x32 = BinaryenSubInt32();
   return caml_copy_int32(x32);
}
CAMLprim value binaryen_stub_14_BinaryenMulInt32(value x33)
{
   int32_t x34 = BinaryenMulInt32();
   return caml_copy_int32(x34);
}
CAMLprim value binaryen_stub_15_BinaryenDivSInt32(value x35)
{
   int32_t x36 = BinaryenDivSInt32();
   return caml_copy_int32(x36);
}
CAMLprim value binaryen_stub_16_BinaryenLtSInt32(value x37)
{
   int32_t x38 = BinaryenLtSInt32();
   return caml_copy_int32(x38);
}
CAMLprim value binaryen_stub_17_BinaryenLeSInt32(value x39)
{
   int32_t x40 = BinaryenLeSInt32();
   return caml_copy_int32(x40);
}
CAMLprim value binaryen_stub_18_BinaryenGtSInt32(value x41)
{
   int32_t x42 = BinaryenGtSInt32();
   return caml_copy_int32(x42);
}
CAMLprim value binaryen_stub_19_BinaryenGeSInt32(value x43)
{
   int32_t x44 = BinaryenGeSInt32();
   return caml_copy_int32(x44);
}
CAMLprim value binaryen_stub_20_BinaryenEqInt32(value x45)
{
   int32_t x46 = BinaryenEqInt32();
   return caml_copy_int32(x46);
}
CAMLprim value binaryen_stub_21_BinaryenNeInt32(value x47)
{
   int32_t x48 = BinaryenNeInt32();
   return caml_copy_int32(x48);
}
CAMLprim value binaryen_stub_22_BinaryenLiteralInt32(value x49)
{
   int32_t x50 = Int32_val(x49);
   struct BinaryenLiteral x53 = BinaryenLiteralInt32(x50);
   return ctypes_copy_bytes(&x53, 24);
}
CAMLprim value binaryen_stub_23_BinaryenLiteralInt64(value x54)
{
   int64_t x55 = Int64_val(x54);
   struct BinaryenLiteral x58 = BinaryenLiteralInt64(x55);
   return ctypes_copy_bytes(&x58, 24);
}
CAMLprim value binaryen_stub_24_BinaryenLiteralFloat32(value x59)
{
   double x60 = Double_val(x59);
   struct BinaryenLiteral x63 = BinaryenLiteralFloat32((float)x60);
   return ctypes_copy_bytes(&x63, 24);
}
CAMLprim value binaryen_stub_25_BinaryenLiteralFloat64(value x64)
{
   double x65 = Double_val(x64);
   struct BinaryenLiteral x68 = BinaryenLiteralFloat64(x65);
   return ctypes_copy_bytes(&x68, 24);
}
CAMLprim value binaryen_stub_26_BinaryenBlock(value x73, value x72, value x71,
                                     value x70, value x69)
{
   void* x74 = CTYPES_ADDR_OF_FATPTR(x73);
   char* x75 = CTYPES_ADDR_OF_FATPTR(x72);
   void** x76 = CTYPES_ADDR_OF_FATPTR(x71);
   size_t x77 = ctypes_size_t_val(x70);
   uint64_t x80 = Uint64_val(x69);
   void* x83 = BinaryenBlock(x74, x75, x76, x77, x80);
   return CTYPES_FROM_PTR(x83);
}
CAMLprim value binaryen_stub_27_BinaryenConst(value x85, value x84)
{
   void* x86 = CTYPES_ADDR_OF_FATPTR(x85);
   void* x87 = CTYPES_ADDR_OF_FATPTR(x84);
   struct BinaryenLiteral x89 = *(struct BinaryenLiteral*)x87;
   void* x90 = BinaryenConst(x86, x89);
   return CTYPES_FROM_PTR(x90);
}
CAMLprim value binaryen_stub_28_BinaryenBinary(value x94, value x93, value x92,
                                      value x91)
{
   void* x95 = CTYPES_ADDR_OF_FATPTR(x94);
   int32_t x96 = Int32_val(x93);
   void* x99 = CTYPES_ADDR_OF_FATPTR(x92);
   void* x100 = CTYPES_ADDR_OF_FATPTR(x91);
   void* x101 = BinaryenBinary(x95, x96, x99, x100);
   return CTYPES_FROM_PTR(x101);
}
CAMLprim value binaryen_stub_29_BinaryenUnreachable(value x102)
{
   void* x103 = CTYPES_ADDR_OF_FATPTR(x102);
   void* x104 = BinaryenUnreachable(x103);
   return CTYPES_FROM_PTR(x104);
}
CAMLprim value binaryen_stub_30_BinaryenReturn(value x106, value x105)
{
   void* x107 = CTYPES_ADDR_OF_FATPTR(x106);
   void* x108 = CTYPES_ADDR_OF_FATPTR(x105);
   void* x109 = BinaryenReturn(x107, x108);
   return CTYPES_FROM_PTR(x109);
}
CAMLprim value binaryen_stub_31_BinaryenIf(value x113, value x112, value x111,
                                  value x110)
{
   void* x114 = CTYPES_ADDR_OF_FATPTR(x113);
   void* x115 = CTYPES_ADDR_OF_FATPTR(x112);
   void* x116 = CTYPES_ADDR_OF_FATPTR(x111);
   void* x117 = CTYPES_ADDR_OF_FATPTR(x110);
   void* x118 = BinaryenIf(x114, x115, x116, x117);
   return CTYPES_FROM_PTR(x118);
}
CAMLprim value binaryen_stub_32_BinaryenLoop(value x121, value x120, value x119)
{
   void* x122 = CTYPES_ADDR_OF_FATPTR(x121);
   char* x123 = CTYPES_ADDR_OF_FATPTR(x120);
   void* x124 = CTYPES_ADDR_OF_FATPTR(x119);
   void* x125 = BinaryenLoop(x122, x123, x124);
   return CTYPES_FROM_PTR(x125);
}
CAMLprim value binaryen_stub_33_BinaryenBreak(value x129, value x128, value x127,
                                     value x126)
{
   void* x130 = CTYPES_ADDR_OF_FATPTR(x129);
   char* x131 = CTYPES_ADDR_OF_FATPTR(x128);
   void* x132 = CTYPES_ADDR_OF_FATPTR(x127);
   void* x133 = CTYPES_ADDR_OF_FATPTR(x126);
   void* x134 = BinaryenBreak(x130, x131, x132, x133);
   return CTYPES_FROM_PTR(x134);
}
CAMLprim value binaryen_stub_34_BinaryenLocalGet(value x137, value x136, value x135)
{
   void* x138 = CTYPES_ADDR_OF_FATPTR(x137);
   int x139 = Long_val(x136);
   uint64_t x142 = Uint64_val(x135);
   void* x145 = BinaryenLocalGet(x138, x139, x142);
   return CTYPES_FROM_PTR(x145);
}
CAMLprim value binaryen_stub_35_BinaryenLocalSet(value x148, value x147, value x146)
{
   void* x149 = CTYPES_ADDR_OF_FATPTR(x148);
   int x150 = Long_val(x147);
   void* x153 = CTYPES_ADDR_OF_FATPTR(x146);
   void* x154 = BinaryenLocalSet(x149, x150, x153);
   return CTYPES_FROM_PTR(x154);
}
CAMLprim value binaryen_stub_36_BinaryenLoad(value x161, value x160, value x159,
                                    value x158, value x157, value x156,
                                    value x155)
{
   void* x162 = CTYPES_ADDR_OF_FATPTR(x161);
   int x163 = Long_val(x160);
   _Bool x166 = Bool_val(x159);
   int x169 = Long_val(x158);
   int x172 = Long_val(x157);
   uint64_t x175 = Uint64_val(x156);
   void* x178 = CTYPES_ADDR_OF_FATPTR(x155);
   void* x179 = BinaryenLoad(x162, x163, x166, x169, x172, x175, x178);
   return CTYPES_FROM_PTR(x179);
}
CAMLprim value binaryen_stub_36_BinaryenLoad_byte7(value* argv, int argc)
{
   value x180 = argv[6];
   value x181 = argv[5];
   value x182 = argv[4];
   value x183 = argv[3];
   value x184 = argv[2];
   value x185 = argv[1];
   value x186 = argv[0];
   return
     binaryen_stub_36_BinaryenLoad(x186, x185, x184, x183, x182, x181, x180);
}
CAMLprim value binaryen_stub_37_BinaryenStore(value x193, value x192, value x191,
                                     value x190, value x189, value x188,
                                     value x187)
{
   void* x194 = CTYPES_ADDR_OF_FATPTR(x193);
   int x195 = Long_val(x192);
   int x198 = Long_val(x191);
   int x201 = Long_val(x190);
   void* x204 = CTYPES_ADDR_OF_FATPTR(x189);
   void* x205 = CTYPES_ADDR_OF_FATPTR(x188);
   uint64_t x206 = Uint64_val(x187);
   void* x209 = BinaryenStore(x194, x195, x198, x201, x204, x205, x206);
   return CTYPES_FROM_PTR(x209);
}
CAMLprim value binaryen_stub_37_BinaryenStore_byte7(value* argv, int argc)
{
   value x210 = argv[6];
   value x211 = argv[5];
   value x212 = argv[4];
   value x213 = argv[3];
   value x214 = argv[2];
   value x215 = argv[1];
   value x216 = argv[0];
   return
     binaryen_stub_37_BinaryenStore(x216, x215, x214, x213, x212, x211, x210);
}
CAMLprim value binaryen_stub_38_BinaryenCall(value x221, value x220, value x219,
                                    value x218, value x217)
{
   void* x222 = CTYPES_ADDR_OF_FATPTR(x221);
   char* x223 = CTYPES_ADDR_OF_FATPTR(x220);
   void** x224 = CTYPES_ADDR_OF_FATPTR(x219);
   size_t x225 = ctypes_size_t_val(x218);
   uint64_t x228 = Uint64_val(x217);
   void* x231 = BinaryenCall(x222, x223, x224, x225, x228);
   return CTYPES_FROM_PTR(x231);
}
CAMLprim value binaryen_stub_39_BinaryenMemoryFill(value x235, value x234, value x233,
                                          value x232)
{
   void* x236 = CTYPES_ADDR_OF_FATPTR(x235);
   void* x237 = CTYPES_ADDR_OF_FATPTR(x234);
   void* x238 = CTYPES_ADDR_OF_FATPTR(x233);
   void* x239 = CTYPES_ADDR_OF_FATPTR(x232);
   void* x240 = BinaryenMemoryFill(x236, x237, x238, x239);
   return CTYPES_FROM_PTR(x240);
}
CAMLprim value binaryen_stub_40_BinaryenMemoryCopy(value x244, value x243, value x242,
                                          value x241)
{
   void* x245 = CTYPES_ADDR_OF_FATPTR(x244);
   void* x246 = CTYPES_ADDR_OF_FATPTR(x243);
   void* x247 = CTYPES_ADDR_OF_FATPTR(x242);
   void* x248 = CTYPES_ADDR_OF_FATPTR(x241);
   void* x249 = BinaryenMemoryCopy(x245, x246, x247, x248);
   return CTYPES_FROM_PTR(x249);
}
CAMLprim value binaryen_stub_41_BinaryenAddFunction(value x256, value x255,
                                           value x254, value x253,
                                           value x252, value x251,
                                           value x250)
{
   void* x257 = CTYPES_ADDR_OF_FATPTR(x256);
   char* x258 = CTYPES_ADDR_OF_FATPTR(x255);
   uint64_t x259 = Uint64_val(x254);
   uint64_t x262 = Uint64_val(x253);
   uintptr_t* x265 = CTYPES_ADDR_OF_FATPTR(x252);
   size_t x266 = ctypes_size_t_val(x251);
   void* x269 = CTYPES_ADDR_OF_FATPTR(x250);
   void* x270 =
   BinaryenAddFunction(x257, x258, x259, x262, x265, x266, x269);
   return CTYPES_FROM_PTR(x270);
}
CAMLprim value binaryen_stub_41_BinaryenAddFunction_byte7(value* argv, int argc)
{
   value x271 = argv[6];
   value x272 = argv[5];
   value x273 = argv[4];
   value x274 = argv[3];
   value x275 = argv[2];
   value x276 = argv[1];
   value x277 = argv[0];
   return
     binaryen_stub_41_BinaryenAddFunction(x277, x276, x275, x274, x273, 
                                          x272, x271);
}
CAMLprim value binaryen_stub_42_BinaryenAddFunctionImport(value x283, value x282,
                                                 value x281, value x280,
                                                 value x279, value x278)
{
   void* x284 = CTYPES_ADDR_OF_FATPTR(x283);
   char* x285 = CTYPES_ADDR_OF_FATPTR(x282);
   char* x286 = CTYPES_ADDR_OF_FATPTR(x281);
   char* x287 = CTYPES_ADDR_OF_FATPTR(x280);
   uint64_t x288 = Uint64_val(x279);
   uint64_t x291 = Uint64_val(x278);
   BinaryenAddFunctionImport(x284, x285, x286, x287, x288, x291);
   return Val_unit;
}
CAMLprim value binaryen_stub_42_BinaryenAddFunctionImport_byte6(value* argv, int argc)
{
   value x295 = argv[5];
   value x296 = argv[4];
   value x297 = argv[3];
   value x298 = argv[2];
   value x299 = argv[1];
   value x300 = argv[0];
   return
     binaryen_stub_42_BinaryenAddFunctionImport(x300, x299, x298, x297, 
                                                x296, x295);
}
CAMLprim value binaryen_stub_43_BinaryenAddFunctionExport(value x303, value x302,
                                                 value x301)
{
   void* x304 = CTYPES_ADDR_OF_FATPTR(x303);
   char* x305 = CTYPES_ADDR_OF_FATPTR(x302);
   char* x306 = CTYPES_ADDR_OF_FATPTR(x301);
   void* x307 = BinaryenAddFunctionExport(x304, x305, x306);
   return CTYPES_FROM_PTR(x307);
}
CAMLprim value binaryen_stub_44_BinaryenAddGlobal(value x312, value x311, value x310,
                                         value x309, value x308)
{
   void* x313 = CTYPES_ADDR_OF_FATPTR(x312);
   char* x314 = CTYPES_ADDR_OF_FATPTR(x311);
   uint64_t x315 = Uint64_val(x310);
   _Bool x318 = Bool_val(x309);
   void* x321 = CTYPES_ADDR_OF_FATPTR(x308);
   void* x322 = BinaryenAddGlobal(x313, x314, x315, x318, x321);
   return CTYPES_FROM_PTR(x322);
}
CAMLprim value binaryen_stub_45_BinaryenGlobalGet(value x325, value x324, value x323)
{
   void* x326 = CTYPES_ADDR_OF_FATPTR(x325);
   char* x327 = CTYPES_ADDR_OF_FATPTR(x324);
   uint64_t x328 = Uint64_val(x323);
   void* x331 = BinaryenGlobalGet(x326, x327, x328);
   return CTYPES_FROM_PTR(x331);
}
CAMLprim value binaryen_stub_46_BinaryenGlobalSet(value x334, value x333, value x332)
{
   void* x335 = CTYPES_ADDR_OF_FATPTR(x334);
   char* x336 = CTYPES_ADDR_OF_FATPTR(x333);
   void* x337 = CTYPES_ADDR_OF_FATPTR(x332);
   void* x338 = BinaryenGlobalSet(x335, x336, x337);
   return CTYPES_FROM_PTR(x338);
}
CAMLprim value binaryen_stub_47_BinaryenDrop(value x340, value x339)
{
   void* x341 = CTYPES_ADDR_OF_FATPTR(x340);
   void* x342 = CTYPES_ADDR_OF_FATPTR(x339);
   void* x343 = BinaryenDrop(x341, x342);
   return CTYPES_FROM_PTR(x343);
}
CAMLprim value binaryen_stub_48_BinaryenSetMemory(value x353, value x352, value x351,
                                         value x350, value x349, value x348,
                                         value x347, value x346, value x345,
                                         value x344)
{
   void* x354 = CTYPES_ADDR_OF_FATPTR(x353);
   int x355 = Long_val(x352);
   int x358 = Long_val(x351);
   char* x361 = CTYPES_ADDR_OF_FATPTR(x350);
   char** x362 = CTYPES_ADDR_OF_FATPTR(x349);
   _Bool* x363 = CTYPES_ADDR_OF_FATPTR(x348);
   void** x364 = CTYPES_ADDR_OF_FATPTR(x347);
   uint32_t* x365 = CTYPES_ADDR_OF_FATPTR(x346);
   size_t x366 = ctypes_size_t_val(x345);
   _Bool x369 = Bool_val(x344);
   BinaryenSetMemory(x354, x355, x358, x361, x362, x363, x364, x365, 
                     x366, x369);
   return Val_unit;
}
CAMLprim value binaryen_stub_48_BinaryenSetMemory_byte10(value* argv, int argc)
{
   value x373 = argv[9];
   value x374 = argv[8];
   value x375 = argv[7];
   value x376 = argv[6];
   value x377 = argv[5];
   value x378 = argv[4];
   value x379 = argv[3];
   value x380 = argv[2];
   value x381 = argv[1];
   value x382 = argv[0];
   return
     binaryen_stub_48_BinaryenSetMemory(x382, x381, x380, x379, x378, 
                                        x377, x376, x375, x374, x373);
}
CAMLprim value binaryen_stub_49_BinaryenSetDebugInfo(value x383)
{
   _Bool x384 = Bool_val(x383);
   BinaryenSetDebugInfo(x384);
   return Val_unit;
}
CAMLprim value binaryen_stub_50_BinaryenModuleAllocateAndWriteText(value x388)
{
   void* x389 = CTYPES_ADDR_OF_FATPTR(x388);
   char* x390 = BinaryenModuleAllocateAndWriteText(x389);
   return CTYPES_FROM_PTR(x390);
}
CAMLprim value binaryen_stub_51_BinaryenModuleAllocateAndWrite(value x392, value x391)
{
   void* x393 = CTYPES_ADDR_OF_FATPTR(x392);
   char* x394 = CTYPES_ADDR_OF_FATPTR(x391);
   struct BinaryenModuleAllocateAndWriteResult x395 =
   BinaryenModuleAllocateAndWrite(x393, x394);
   return ctypes_copy_bytes(&x395, 24);
}
CAMLprim value binaryen_stub_52_clean_binary_result(value x396)
{
   void* x397 = CTYPES_ADDR_OF_FATPTR(x396);
   struct BinaryenModuleAllocateAndWriteResult x399 =
   *(struct BinaryenModuleAllocateAndWriteResult*)x397;
   clean_binary_result(x399);
   return Val_unit;
}
CAMLprim value binaryen_stub_53_dump_bytes_to_path(value x403, value x402, value x401)
{
   void* x404 = CTYPES_ADDR_OF_FATPTR(x403);
   size_t x405 = ctypes_size_t_val(x402);
   char* x408 = CTYPES_ADDR_OF_FATPTR(x401);
   dump_bytes_to_path(x404, x405, x408);
   return Val_unit;
}
