#!/bin/bash

echo "Starting to install dependencies"
echo

PEAR_CONFIG_FILE=".pearrc"

# clean up prior installation
rm -rf pear $PEAR_CONFIG_FILE || exit 1

# make new local config
pear config-create $(pwd)/ $PEAR_CONFIG_FILE || exit 1
pear -c $PEAR_CONFIG_FILE config-set auto_discover 1 || exit 1

pear -c $PEAR_CONFIG_FILE channel-discover pear.phpunit.de || exit 1
pear -c $PEAR_CONFIG_FILE install phpunit/PHPUnit || exit 1

# patch PHP's include_path in phpunit script
PEAR_DIR=$(pwd)/pear
sed '2a\
set_include_path(dirname(__FILE__) . "/php" . PATH_SEPARATOR . get_include_path());
' $PEAR_DIR/phpunit > $PEAR_DIR/phpunit2 || exit 1
mv $PEAR_DIR/phpunit2 $PEAR_DIR/phpunit || exit 1
chmod 755 $PEAR_DIR/phpunit || exit 1

cd $ORIG_DIR

echo
echo "Done installing dependencies"
