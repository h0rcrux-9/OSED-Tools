#!/usr/bin/bash
cp /home/h0rcrux/.zsh_history ./.zsh_history

git submodule init && git submodule update --recursive --remote 
git add . && git commit -m "Update OSED"
git push
