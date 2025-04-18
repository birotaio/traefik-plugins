pushd $SOURCE_FOLDER
cp -r . $TMPFOLDER
export INCLUDE_HIDDEN_LIST=".traefik.yml"
popd
