# Helper function for image building

def check_file_ownership_tar(d, archiveFilePath):
    """
    Verifies file ownership meta-data in image tarball matches users
    and groups in shadow database (/etc/passwd and /etc/group files).
    """
    import sys, os, tarfile
    bb.debug(1, "Running check_file_ownership() on image '{0!s}'".format(archiveFilePath))

    try:
        archiveName = os.path.basename(archiveFilePath)
        if not archiveName:
            archiveName = archiveFilePath

        # maps
        unameMap = {}  # username -> passwd file entry array
        gnameMap = {}  # groupname -> group file entry array
        uidMap = {}  # uid -> passwd file entry array
        gidMap   = {}  # gid -> group file entry array
        fileMap = {}  # filepath -> TarInfo object

        def read_shadow_file(fdName, fd, colCount, mapsList):
            """ Reads a colon (:) delimited shadow database file into mapsList """
            for mapObj,_ in mapsList:
                if len(mapObj) != 0:
                    raise Exception("Already read '{0!s}' file.".format(fdName))

            for line in fd:
                line = line.decode("utf-8").strip()
                words = line.split(":")

                if len(words) != colCount:
                    raise Exception("Malformed '{0!s}' file. Expected {1!s} cols.".format(fdName, colCount))

                for mapObj,mapKeyCol in mapsList:
                    mapKey = words[mapKeyCol]
                    if len(mapKey) < 1:
                        raise Exception("Map key in '{0!s}' must be at least one char long.".format(fdName))

                    if mapKey in mapObj:
                        raise Exception("Malformed '{0!s}' file. Did not expect to find '{0!s}' in map.".format(fdName, mapKey))

                    mapObj[mapKey] = words

            for mapObj,_ in mapsList:
                if len(mapObj) == 0:
                    raise Exception("'{0!s}' is empty.".format(fdName))

        bb.debug(1, "Read the archive and populate maps")
        with tarfile.open(name=archiveFilePath, mode='r:*') as tar:
            for info in tar:
                if info.name in fileMap:
                    raise Exception("Duplicate entry for '{0!s}' found.".format(info.name))

                fileMap[info.name] = info

                # populate shadow db maps
                if    info.name == './etc/passwd':  read_shadow_file(fdName=info.name, fd=tar.extractfile(info), colCount=7, mapsList=[(unameMap, 0), (uidMap, 2), ])
                elif  info.name == './etc/group':   read_shadow_file(fdName=info.name, fd=tar.extractfile(info), colCount=4, mapsList=[(gnameMap, 0), (gidMap, 2), ])

        bb.debug(1, "Check for no shadow db")
        shadowItemCount = 0
        for mapObj in [unameMap, gnameMap, uidMap, gidMap]:
            shadowItemCount = shadowItemCount + len(mapObj)
        if shadowItemCount == 0:
            bb.warn(1, "check_file_ownership(): Skip; no shadow database in image '{0!s}'".format(archiveName))
            return

        bb.debug(1, "Map sanity check")
        for mapObj in [unameMap, gnameMap, uidMap, gidMap, fileMap]:
            if len(mapObj) < 1:
                raise Exception("Uh oh. Empty map found.")

        def badFileError(errorMessage, info, shadowEntry=None):
            linkname = ""
            if info.linkname:
                linkname = " -> {0!s}".format(info.linkname)

            bb.error("BAD FILE '{0!s}': {1!s}".format(info.name, errorMessage))
            bb.error("## {info.uid!s}:{info.gid!s} ({info.uname!s}:{info.gname!s}) 0{info.mode:o} {info.name!s}{linkname!s}".format(info=info, linkname=linkname))
            if shadowEntry:
                bb.error("## {0!s}".format(shadowEntry))

        bb.debug(1, "Check for bad files")
        for filepath,info in fileMap.items():
            if not info.uname in unameMap:
                badFileError("uname not in unameMap", info)
                continue

            if not info.gname in gnameMap:
                badFileError("gname not in gnameMap", info)
                continue

            if not str(info.uid) in uidMap:
                badFileError("Uid '{0!s}' not found".format(info.uid), info)

            if not str(info.gid) in gidMap:
                badFileError("Gid '{0!s}' not found".format(info.gid), info)

            unameEntry = unameMap[info.uname]
            gnameEntry = gnameMap[info.gname]

            if str(info.uid) != unameEntry[2]:
                badFileError("uid mismatch, expecting '{0!s}' for uname '{1!s}'".format(unameEntry[2], info.uname), info, unameEntry)

            if str(info.gid) != gnameEntry[2]:
                badFileError("gid mismatch, expecting '{0!s}' for gname '{1!s}'".format(gnameEntry[2], info.gname), info, gnameEntry)

        bb.debug(1, "Successfully verified image '{0!s}'".format(archiveName))

    # Error on any exceptions
    except Exception as e:
        bb.error("check_file_ownership() exception: {0!s}".format(e))
