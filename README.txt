Dependencies: 
	Window 10 or 11 
	python3 
	python3 -m pip install pyserial rich

Note:
	Must run with git bash ( we need tee )

Example usage: 
	Flash full:
		python3 .\cavli_flash.py --fw_path=emmc --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash
	Skip modem:
		python3 .\cavli_flash.py --fw_path=emmc --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash --skip-nhlos
	Flash multi device
		python3 .\cavli_flash_multi_edl.py --fw_path=emmc --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash