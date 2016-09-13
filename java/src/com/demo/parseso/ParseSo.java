package com.demo.parseso;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.demo.parseso.ElfType32.Elf32_Sym;
import com.demo.parseso.ElfType32.elf32_phdr;
import com.demo.parseso.ElfType32.elf32_shdr;

public class ParseSo {

    public static ElfType32 type_32 = new ElfType32();

    public static void main(String[] args) {

        byte[] fileByteArys = Utils.readFile("so/libhello-jni.so");
        if (fileByteArys == null) {
            System.out.println("read file byte failed...");
            return;
        }

        /**
         * 先解析so文件
         * 然后初始化AddSection中的一些信息
         * 最后在AddSection
         */
        parseSo(fileByteArys);

        //初始化AddSection中的变量
        AddSection.sectionHeaderOffset = Utils.byte2Int(type_32.hdr.e_shoff);
        AddSection.stringSectionInSectionTableIndex = Utils.byte2Short(type_32.hdr.e_shstrndx);
        AddSection.stringSectionOffset = Utils.byte2Int(type_32.shdrList
                .get(AddSection.stringSectionInSectionTableIndex).sh_offset);
        //找到第一个和最后一个类型为Load的Program header的index
        boolean flag = true;
        for (int i = 0; i < type_32.phdrList.size(); i++) {
            if (Utils.byte2Int(type_32.phdrList.get(i).p_type) == 1) {//LOAD的type==1,可在elf格式文档中找到
                if (flag) {
                    AddSection.firstLoadInPHIndex = i;
                    flag = false;
                } else {
                    AddSection.lastLoadInPHIndex = i;
                }
            }
        }
        int lastLoadVaddr = Utils.byte2Int(type_32.phdrList.get(AddSection.lastLoadInPHIndex).p_vaddr);
        int lastLoadMem = Utils.byte2Int(type_32.phdrList.get(AddSection.lastLoadInPHIndex).p_memsz);
        int lastLoadAlign = Utils.byte2Int(type_32.phdrList.get(AddSection.lastLoadInPHIndex).p_align);
        AddSection.addSectionStartAddr = Utils.align(lastLoadVaddr + lastLoadMem, lastLoadAlign);
        System.out.println("start addr hex:" + Utils.bytes2HexString(Utils.int2Byte(AddSection.addSectionStartAddr)));

        /**
         * 添加一个Section
         * 以下的顺序不可乱，不然会出错的
         * 1、添加一个Section Header
         * 2、直接在文件的末尾追加一个section
         * 3、修改String段的长度
         * 4、修改Elf Header中的section count
         */
        fileByteArys = AddSection.addSectionHeader(fileByteArys);
        fileByteArys = AddSection.addNewSectionForFileEnd(fileByteArys);
        fileByteArys = AddSection.changeStrtabLen(fileByteArys);
        fileByteArys = AddSection.changeElfHeaderSectionCount(fileByteArys);
        fileByteArys = AddSection.changeProgramHeaderLoadInfo(fileByteArys);

        Utils.saveFile("so/libhello-jnis.so", fileByteArys);

    }

    private static void parseSo(byte[] fileByteArys) {
        parseHeader(fileByteArys);
        parseProgramHeaderList(fileByteArys);
        parseSectionHeaderList(fileByteArys);
        parseStringTableList(fileByteArys);
        parseSymbolTableList(fileByteArys);

        System.out.println("+++++++++++++++++++Elf Header+++++++++++++++++");
        System.out.println("header:\n" + type_32.hdr);

        System.out.println();
        System.out.println("+++++++++++++++++++Program Header+++++++++++++++++");
        type_32.printPhdrList();

        System.out.println();
        System.out.println("+++++++++++++++++++Section Header++++++++++++++++++");
        type_32.printShdrList();

        System.out.println();
        for (Map.Entry<List<ElfType32.elf32_strtb>, Integer> entry : type_32.strtbs.entrySet()) {
            String name = getStrFromShStrTab(entry.getValue());
            System.out.println("+++++++++++++++++++String Table: " + name + " ++++++++++++++++++");
            printStrtbs(entry.getKey());
        }

        System.out.println();
        for (Map.Entry<List<Elf32_Sym>, Integer> entry : type_32.symtbs.entrySet()) {
            String name = getStrFromShStrTab(entry.getValue());
            System.out.println("+++++++++++++++++++Symbol Table: " + name + " ++++++++++++++++++");
            printSymtbs(entry.getKey());
        }

    }

    /**
     * 解析Elf的头部信息
     * 
     * public byte[] e_ident = new byte[16];
     * public short e_type;
     * public short e_machine;
     * public int e_version;
     * public int e_entry;
     * public int e_phoff;
     * public int e_shoff;
     * public int e_flags;
     * public short e_ehsize;
     * public short e_phentsize;
     * public short e_phnum;
     * public short e_shentsize;
     * public short e_shnum;
     * public short e_shstrndx;
     * 
     */
    private static void parseHeader(byte[] data) {
        if (data == null) {
            throw new Error("data is null");
        }
        type_32.hdr.e_ident = Utils.copyBytes(data, 0, 16);//魔数
        type_32.hdr.e_type = Utils.copyBytes(data, 16, 2);
        type_32.hdr.e_machine = Utils.copyBytes(data, 18, 2);
        type_32.hdr.e_version = Utils.copyBytes(data, 20, 4);
        type_32.hdr.e_entry = Utils.copyBytes(data, 24, 4);
        type_32.hdr.e_phoff = Utils.copyBytes(data, 28, 4);
        type_32.hdr.e_shoff = Utils.copyBytes(data, 32, 4);
        type_32.hdr.e_flags = Utils.copyBytes(data, 36, 4);
        type_32.hdr.e_ehsize = Utils.copyBytes(data, 40, 2);
        type_32.hdr.e_phentsize = Utils.copyBytes(data, 42, 2);
        type_32.hdr.e_phnum = Utils.copyBytes(data, 44, 2);
        type_32.hdr.e_shentsize = Utils.copyBytes(data, 46, 2);
        type_32.hdr.e_shnum = Utils.copyBytes(data, 48, 2);
        type_32.hdr.e_shstrndx = Utils.copyBytes(data, 50, 2);
    }

    public static void parseProgramHeaderList(byte[] data) {
        int offset = Utils.byte2Int(type_32.hdr.e_phoff);
        int item_size = Utils.byte2Short(type_32.hdr.e_phentsize);
        int item_count = Utils.byte2Short(type_32.hdr.e_phnum);
        for (int i = 0; i < item_count; i++) {
            type_32.phdrList.add(parseProgramHeader(data, offset));
            offset += item_size;
        }
    }

    /**
     * public int p_type;
     * public int p_offset;
     * public int p_vaddr;
     * public int p_paddr;
     * public int p_filesz;
     * public int p_memsz;
     * public int p_flags;
     * public int p_align;
     */
    private static elf32_phdr parseProgramHeader(byte[] data, int offset) {
        ElfType32.elf32_phdr phdr = new ElfType32.elf32_phdr();
        phdr.p_type = Utils.copyBytes(data, offset, 4);
        phdr.p_offset = Utils.copyBytes(data, offset + 4, 4);
        phdr.p_vaddr = Utils.copyBytes(data, offset + 8, 4);
        phdr.p_paddr = Utils.copyBytes(data, offset + 12, 4);
        phdr.p_filesz = Utils.copyBytes(data, offset + 16, 4);
        phdr.p_memsz = Utils.copyBytes(data, offset + 20, 4);
        phdr.p_flags = Utils.copyBytes(data, offset + 24, 4);
        phdr.p_align = Utils.copyBytes(data, offset + 28, 4);
        return phdr;

    }

    public static void parseSectionHeaderList(byte[] data) {
        int offset = Utils.byte2Int(type_32.hdr.e_shoff);
        int item_size = Utils.byte2Short(type_32.hdr.e_shentsize);
        int item_count = Utils.byte2Short(type_32.hdr.e_shnum);//头部的个数
        for (int i = 0; i < item_count; i++) {
            type_32.shdrList.add(parseSectionHeader(data, offset));
            offset += item_size;
        }
    }

    /**
     * public byte[] sh_name = new byte[4];
     * public byte[] sh_type = new byte[4];
     * public byte[] sh_flags = new byte[4];
     * public byte[] sh_addr = new byte[4];
     * public byte[] sh_offset = new byte[4];
     * public byte[] sh_size = new byte[4];
     * public byte[] sh_link = new byte[4];
     * public byte[] sh_info = new byte[4];
     * public byte[] sh_addralign = new byte[4];
     * public byte[] sh_entsize = new byte[4];
     */
    private static elf32_shdr parseSectionHeader(byte[] data, int offset) {
        ElfType32.elf32_shdr shdr = new ElfType32.elf32_shdr();
        shdr.sh_name = Utils.copyBytes(data, offset, 4);
        shdr.sh_type = Utils.copyBytes(data, offset + 4, 4);
        shdr.sh_flags = Utils.copyBytes(data, offset + 8, 4);
        shdr.sh_addr = Utils.copyBytes(data, offset + 12, 4);
        shdr.sh_offset = Utils.copyBytes(data, offset + 16, 4);
        shdr.sh_size = Utils.copyBytes(data, offset + 20, 4);
        shdr.sh_link = Utils.copyBytes(data, offset + 24, 4);
        shdr.sh_info = Utils.copyBytes(data, offset + 28, 4);
        shdr.sh_addralign = Utils.copyBytes(data, offset + 32, 4);
        shdr.sh_entsize = Utils.copyBytes(data, offset + 36, 4);
        return shdr;
    }

    public static void parseSymbolTableList(byte[] data) {
        for (ElfType32.elf32_shdr item : type_32.shdrList) {
            if (Utils.byte2Int(item.sh_type) == ElfType32.SHT_DYNSYM) {
                List<ElfType32.Elf32_Sym> syms = new ArrayList<>();
                int offset = Utils.byte2Int(item.sh_offset);
                int size = Utils.byte2Int(item.sh_size);
                int item_size = Utils.byte2Int(item.sh_entsize);
                if (size % item_size != 0) {
                    throw new Error("symbol table size error");
                }
                int item_count = size / item_size;
                for (int i = 0; i < item_count; i++) {
                    ElfType32.Elf32_Sym sym = parseSymbolTable(data, offset);
                    syms.add(sym);
                    offset += item_size;
                }
                type_32.symtbs.put(syms, Utils.byte2Int(item.sh_name));
            }
        }
    }

    private static ElfType32.Elf32_Sym parseSymbolTable(byte[] data, int offset) {
        Elf32_Sym sym = new Elf32_Sym();
        sym.st_name = Utils.copyBytes(data, offset, 4);
        sym.st_value = Utils.copyBytes(data, offset + 4, 4);
        sym.st_size = Utils.copyBytes(data, offset + 8, 4);
        sym.st_info = data[offset + 12];
        sym.st_other = data[offset + 13];
        sym.st_shndx = Utils.copyBytes(data, offset + 14, 2);
        return sym;
    }

    public static void parseStringTableList(byte[] data) {
        for (int i = 0; i < type_32.shdrList.size(); i++) {
            elf32_shdr item = type_32.shdrList.get(i);
            if (Utils.byte2Int(item.sh_type) == ElfType32.SHT_STRTAB) {
                int shstrIndex = Utils.byte2Short(type_32.hdr.e_shstrndx);
                int offset = Utils.byte2Int(item.sh_offset);
                int size = Utils.byte2Int(item.sh_size);
                List<ElfType32.elf32_strtb> strtbs = parseStringTableList(data, offset, size);
                type_32.strtbs.put(strtbs, Utils.byte2Int(item.sh_name));
                if (shstrIndex == i) {
                    type_32.shstrtab = Utils.copyBytes(data, offset, size);
                }
            }
        }
    }

    public static String getStrFromShStrTab(int offset) {
        if (type_32.shstrtab != null && type_32.shstrtab.length > offset) {
            int index = offset;
            while (index < type_32.shstrtab.length) {
                int v = type_32.shstrtab[index];
                index++;
                if (v == 0) {
                    return new String(type_32.shstrtab, offset, (index - offset));
                }
            }
        }
        return null;
    }

    public static List<ElfType32.elf32_strtb> parseStringTableList(byte[] data, int offset, int size) {
        List<ElfType32.elf32_strtb> list = new ArrayList<>();
        int i = offset;
        int j = i;
        while (j < (size + offset)) {
            int v = data[j];
            j++;
            if (v == 0) {
                ElfType32.elf32_strtb strtb = new ElfType32.elf32_strtb();
                strtb.len = j - i;
                strtb.str_name = Utils.copyBytes(data, i, strtb.len);
                list.add(strtb);

                i = j;
            }
        }
        return list;
    }

    public static void printSymtbs(List<Elf32_Sym> list) {
        for (int i = 0; i < list.size(); i++) {
            System.out.println();
            System.out.println("The " + i + " Symbol Item:");
            System.out.println(list.get(i).toString());
        }
    }

    public static void printStrtbs(List<ElfType32.elf32_strtb> list) {
        for (int i = 0; i < list.size(); i++) {
            System.out.println();
            System.out.println("The " + i + " String Item:");
            System.out.println(list.get(i).toString());
        }
    }
}
