
from .base import Converter
from ...helpers import iterate_files, get_ip, get_screenshot

# Needed for decoding base64-strings in Python3
from codecs import decode

import os


class ImagesConverter(Converter):

    # The Images converter is special in that it creates a directory and there's
    # special code in the Shodan CLI that relies on the "dirname" property to let
    # the user know where the images have been stored.
    dirname = None
    
    def process(self, files):
        # Get the filename from the already-open file handle and use it as
        # the directory name to store the images.
        self.dirname = self.fout.name[:-7] + '-images'

        # Remove the original file that was created
        self.fout.close()
        os.unlink(self.fout.name)

        # Create the directory if it doesn't yet exist
        if not os.path.exists(self.dirname):
            os.mkdir(self.dirname)

        # Close the existing file as the XlsxWriter library handles that for us
        self.fout.close()

        # Loop through all the banners in the data file
        for banner in iterate_files(files):
            screenshot = get_screenshot(banner)
            if screenshot:
                filename = '{}/{}-{}'.format(self.dirname, get_ip(banner), banner['port'])

                # If a file with the name already exists then count up until we
                # create a new, unique filename
                counter = 0
                tmpname = filename
                while os.path.exists(tmpname + '.jpg'):
                    tmpname = '{}-{}'.format(filename, counter)
                    counter += 1
                filename = tmpname + '.jpg'

                fout = open(filename, 'wb')
                fout.write(decode(screenshot['data'].encode(), 'base64'))
                fout.close()
