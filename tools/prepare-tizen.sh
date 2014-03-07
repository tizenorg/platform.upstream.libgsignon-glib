# $1 corresponds to libgsignon-glib-<ver>.tar.gz 
# $2 is the destination folder
# NOTE: all the files will be extracted under destination folder (instead of destfolder/libgsignon-glib-<version>)

if [ $# -ne 2 -o -z "$1" -o -z "$2" ]; then
    echo "Invalid arguments supplied"
    echo "Usage: ./prepare-tizen.sh libgsignon-glib-<version>.tar.gz /absolute/path/to/destfolder"
    echo "NOTE: All the files will be extracted under destfolder (instead of destfolder/libgsignon-glib-<version>)"
    exit
fi

currdir=`pwd`;
echo "CURR dir = $currdir"

mkdir -p $2 && \
cd $2 && \
git rm -r *; rm -rf packaging;
tar -xzvf $currdir/$1 -C $2 --strip-components 1 && \
mkdir -p packaging && \
cp -f dists/rpm/libgsignon-glib-tizen.spec packaging/libgsignon-glib.spec && \
cp -f dists/rpm/libgsignon-glib-tizen.changes packaging/libgsignon-glib.changes && \
cp $currdir/.gitignore $2/ && \
git add -f *;
