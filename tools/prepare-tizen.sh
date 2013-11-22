# $1 corresponds to libgsignon-glib-<ver>.tar.gz 
# $2 is the destination folder
# NOTE: all the files will be extracted under destination folder (instead of destfolder/libgsignon-glib-<version>)

if [ $# -ne 2 -o -z "$1" -o -z "$2" ]; then
    echo "Invalid arguments supplied"
    echo "Usage: ./prepare-tizen.sh libgsignon-glib-<version>.tar.gz destfolder"
    echo "NOTE: All the files will be extracted under destfolder (instead of destfolder/libgsignon-glib-<version>)"
    exit
fi

currdir = `pwd`;
echo "CURR dir = $currdir"

mkdir -p $2 && \
cd $2 && \
git rm -r * && \
tar -xzvf $1 -C $2 --strip-components 1 && \
mkdir -p packaging && \
cd packaging && \
ln -s ../dists/rpm/libgsignon-glib-tizen.spec libgsignon-glib.spec && \
ln -s ../dists/rpm/libgsignon-glib-tizen.changes libgsignon-glib.changes && \
cd .. && git add *;

