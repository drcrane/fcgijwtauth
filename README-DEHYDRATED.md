# dehydrated

Execute this in docker to make a re-usable image:

    docker run -it --name dehydrated --workdir /home/app -v $(pwd):/home/app alpine:latest /bin/ash
    subprojects/dehydrated/getcert.sh

Steps that need to be followed... in the beginning above will fail but should
install all requirements and dehydrated.

    cd subprojects/dehydrated/
    ./dehydrated --config config --register --accept-terms

To renew and re-use the container:

    docker start -i dehydrated
    subprojects/dehydrated/getcert.sh

