Dependencies: 
	Window 10 or 11 
	python3 
	pip install pyserial

Note:
	Must run with git bash ( we need tee )

Example usage: 
	Without QCN backup/restore
		python cavli_flash.py D:\tmp\c10qm_v1_bin patch_p2K_b128K.xml rawprogram_nand_p2K_b128K.xml 
	With QCN backup/restore: 
		python cavli_flash.py D:\tmp\c10qm_v1_bin patch_p2K_b128K.xml rawprogram_nand_p2K_b128K.xml 1
