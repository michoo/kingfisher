#!/usr/bin/env bash

vhs ./kingfisher-usage-01.tape
vhs ./kingfisher-usage-access-map-01.tape
echo "Demos generated. Preparing browser recording in 5 seconds..."
sleep 5
#npm i -D playwright
#npx playwright install
node ./record.mjs