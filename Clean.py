import os
import shutil

import config


def process(rawPath, unusedpath, label, minn, maxn):
    unusedpath = unusedpath + label
    os.mkdir(unusedpath)
    idx = 0
    cnt = 0
    dirpath = rawPath + label + str(idx)
    while os.path.exists(dirpath):
        if label != "Benign" and idx > 2:
            break
        print("Process", os.path.basename(dirpath))

        files = os.listdir(dirpath)

        for f in files:
            filename = os.path.join(dirpath, f)
            filesize = os.path.getsize(filename)

            if filesize <= minn or filesize >= maxn:
                shutil.move(filename, unusedpath)
                cnt += 1

        idx += 1
        dirpath = rawPath + label + str(idx)

    print(label, cnt, "\n")


def clean(args):
    print("Clean Data\n")
    cleanList = config.CleanList

    if os.path.exists(args.unusedDataPath) == True:
        shutil.rmtree(args.unusedDataPath)
    os.mkdir(args.unusedDataPath)

    for key, value in cleanList.items():
        process(
            args.rawDataPath,
            args.unusedDataPath,
            key,
            value[0],
            value[1],
        )
