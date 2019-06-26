FROM python:3.7-slim-stretch

RUN apt-get update \
&& apt-get -y upgrade

RUN apt-get -y install automake libtool make gcc flex bison libssl-dev wget

RUN wget -q https://curl.haxx.se/download/curl-7.65.1.tar.gz \
&& tar -xvf curl-7.65.1.tar.gz \
&& rm curl-7.65.1.tar.gz \
&& cd curl-7.65.1 \
&& ./configure \
&& make \
&& make install

RUN wget -q https://codeload.github.com/VirusTotal/yara/tar.gz/v3.10.0 -O yara.tar.gz \
&& file yara.tar.gz \
&& tar -xvf yara.tar.gz \
&& rm yara.tar.gz

COPY url.c yara-3.10.0/libyara/modules/

RUN cd yara-3.10.0 \
&& echo 'MODULE(url)' >> libyara/modules/module_list \
&& sed -i 's/# Add your modules here:/MODULES += modules\/url.c/' libyara/Makefile.am \
&& cd ..

RUN cd yara-3.10.0 \
&& ./bootstrap.sh \
&& ./configure --enable-url \
&& make \
&& make install \
&& cd ..

RUN echo "/usr/local/lib" >> /etc/ld.so.conf \
&& ldconfig

RUN pip install --global-option="build" --global-option="--dynamic-linking" yara-python

RUN python -c 'import yara'

