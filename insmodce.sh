#!/bin/bash
rmmod ce
rmmod phytium_ce
echo "insmod ce.ko"
insmod ce.ko
echo "insmod phytium_ce.ko"
insmod phytium_ce.ko
