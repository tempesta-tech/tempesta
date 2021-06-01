Huffman decoder state machine generator
---------------------------------------

The `hpack_tbl.h` file contains objects generated bu `hgen.c`.

To update the header, remove everything from `hpack_tbl.h` after 
`DO NOT EDIT IT BY HANDS!` statement and put output of the `hgen.c` there. Don't
forget to about include guards in the end of the file.

	 make && hgen >> ../hpack_tbl.h


