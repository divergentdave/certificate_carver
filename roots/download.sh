#!/bin/sh
curl https://ct.googleapis.com/logs/argon2022/ct/v1/get-roots > argon-xenon.json
curl https://dodo.ct.comodo.com/ct/v1/get-roots > dodo.json
curl https://ct.googleapis.com/icarus/ct/v1/get-roots > icarus.json
curl https://mammoth.ct.comodo.com/ct/v1/get-roots > mammoth-sabre.json
curl https://nessie2022.ct.digicert.com/log/ct/v1/get-roots > nessie-yeti.json
curl https://ct.cloudflare.com/logs/nimbus2022/ct/v1/get-roots > nimbus.json
curl https://ct.googleapis.com/pilot/ct/v1/get-roots > pilot-daedalus.json
