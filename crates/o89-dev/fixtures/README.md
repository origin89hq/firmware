# Fixtures

`partition-table.bin` is the partition table sector of the comms image as
`espflash save-image --merge --flash-size 8mb --partition-table
firmwares/o89-comms/partitions.csv` lays it out: the 4 KiB at `0x8000` of
the merged image, which is byte for byte what the bench tool reads back off
a module it flashed (F-085).

It is here so that the reader of that table is tested against the bytes the
generator really produces — its checksum entry included — rather than
against bytes this repository wrote to match its own reader. Regenerate it
the same way if the table in `firmwares/o89-comms/partitions.csv` changes.
