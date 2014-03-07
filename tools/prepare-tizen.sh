# $1 corresponds to libgsignon-glib-<ver>.tar.gz 
# $2 is the destination folder
# NOTE: all the files will be extracted under destination folder (instead of destfolder/libgsignon-glib-<version>)

if [ $# -ne 2 -o -z "$1" -o -z "$2" ]; then
    echo "Invalid arguments supplied"
    echo "Usage: ./prepare-tizen.sh <arcive> <destination>"
    echo "NOTE: All the files will be extracted under destfolder (instead of destfolder/libgsignon-glib-<version>)"
    exit
fi

mkdir -p $2 && \
cd $2 && \
git rm -f -r *; rm -rf packaging;
tar -xzvf $1 -C $2 --strip-components 1 && \
mkdir -p packaging && \
cp -f dists/rpm/libgsignon-glib-tizen.spec packaging/libgsignon-glib.spec && \
cp -f dists/rpm/libgsignon-glib-tizen.changes packaging/libgsignon-glib.changes && \
git add -f *;
