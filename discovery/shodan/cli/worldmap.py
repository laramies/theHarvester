#!/usr/bin/env python
'''
F-Secure Virus World Map console edition

See README.md for more details

Copyright 2012-2013 Jyrki Muukkonen

Released under the MIT license.
See LICENSE.txt or http://www.opensource.org/licenses/mit-license.php

ASCII map in map-world-01.txt is copyright:
 "Map 1998 Matthew Thomas. Freely usable as long as this line is included"

'''
import curses
import locale
import random
import time

from shodan.helpers import get_ip


MAPS = {
    'world': {
        # offset (as (y, x) for curses...)
        'corners': (1, 4, 23, 73),
        # lat top, lon left, lat bottom, lon right
        'coords': [90.0, -180.0, -90.0, 180.0],
        'data': '''
               . _..::__:  ,-"-"._       |7       ,     _,.__             
       _.___ _ _<_>`!(._`.`-.    /        _._     `_ ,_/  '  '-._.---.-.__
     .{     " " `-==,',._\{  \  / {)     / _ ">_,-' `                mt-2_
      \_.:--.       `._ )`^-. "'      , [_/(                       __,/-' 
     '"'     \         "    _L       oD_,--'                )     /. (|   
              |           ,'         _)_.\\._<> 6              _,' /  '   
              `.         /          [_/_'` `"(                <'}  )      
               \\    .-. )          /   `-'"..' `:._          _)  '       
        `        \  (  `(          /         `:\  > \  ,-^.  /' '         
                  `._,   ""        |           \`'   \|   ?_)  {\         
                     `=.---.       `._._       ,'     "`  |' ,- '.        
                       |    `-._        |     /          `:`<_|h--._      
                       (        >       .     | ,          `=.__.`-'\     
                        `.     /        |     |{|              ,-.,\     .
                         |   ,'          \   / `'            ,"     \     
                         |  /             |_'                |  __  /     
                         | |                                 '-'  `-'   \.
                         |/                                        "    / 
                         \.                                            '  
                                                                          
                          ,/           ______._.--._ _..---.---------._   
         ,-----"-..?----_/ )      _,-'"             "                  (  
    Map 1998 Matthew Thomas. Freely usable as long as this line is included
'''
    }
}


class AsciiMap(object):
    """
    Helper class for handling map drawing and coordinate calculations
    """
    def __init__(self, map_name='world', map_conf=None, window=None, encoding=None):
        if map_conf is None:
            map_conf = MAPS[map_name]
        self.map = map_conf['data']
        self.coords = map_conf['coords']
        self.corners = map_conf['corners']
        if window is None:
            window = curses.newwin(0, 0)
        self.window = window

        self.data = []
        self.data_timestamp = None

        # JSON contents _should_ be UTF8 (so, python internal unicode here...)
        if encoding is None:
            encoding = locale.getpreferredencoding()
        self.encoding = encoding

        # check if we can use transparent background or not
        if curses.can_change_color():
            curses.use_default_colors()
            background = -1
        else:
            background = curses.COLOR_BLACK

        tmp_colors = [
            ('red', curses.COLOR_RED, background),
            ('blue', curses.COLOR_BLUE, background),
            ('pink', curses.COLOR_MAGENTA, background)
        ]

        self.colors = {}
        if curses.has_colors():
            for i, (name, fgcolor, bgcolor) in enumerate(tmp_colors, 1):
                curses.init_pair(i, fgcolor, bgcolor)
                self.colors[name] = i

    def latlon_to_coords(self, lat, lon):
        """
        Convert lat/lon coordinates to character positions.
        Very naive version, assumes that we are drawing the whole world
        TODO: filter out stuff that doesn't fit
        TODO: make it possible to use "zoomed" maps
        """
        width = (self.corners[3]-self.corners[1])
        height = (self.corners[2]-self.corners[0])

        # change to 0-180, 0-360
        abs_lat = -lat+90
        abs_lon = lon+180
        x = (abs_lon/360.0)*width + self.corners[1]
        y = (abs_lat/180.0)*height + self.corners[0]
        return int(x), int(y)

    def set_data(self, data):
        """
        Set / convert internal data.
        For now it just selects a random set to show.
        """
        entries = []

        # Grab 5 random banners to display
        for banner in random.sample(data, min(len(data), 5)):
            desc = '{} -> {} / {}'.format(get_ip(banner), banner['port'], banner['location']['country_code'])
            if banner['location']['city']:
                desc += ' {}'.format(banner['location']['city'])
            
            if 'tags' in banner and banner['tags']:
                desc += ' / {}'.format(','.join(banner['tags']))
            
            entry = (
                float(banner['location']['latitude']),
                float(banner['location']['longitude']),
                '*',
                desc,
                curses.A_BOLD,
                'red',
            )
            entries.append(entry)
        self.data = entries

    def draw(self, target):
        """ Draw internal data to curses window """
        self.window.clear()
        self.window.addstr(0, 0, self.map)

        # FIXME: position to be defined in map config?
        row = self.corners[2]-6
        items_to_show = 5
        for lat, lon, char, desc, attrs, color in self.data:
            # to make this work almost everywhere. see http://docs.python.org/2/library/curses.html
            if desc:
                desc = desc.encode(self.encoding, 'ignore')
            if items_to_show <= 0:
                break
            char_x, char_y = self.latlon_to_coords(lat, lon)
            if self.colors and color:
                attrs |= curses.color_pair(self.colors[color])
            self.window.addstr(char_y, char_x, char, attrs)
            if desc:
                det_show = "%s %s" % (char, desc)
            else:
                det_show = None

            if det_show is not None:
                try:
                    self.window.addstr(row, 1, det_show, attrs)
                    row += 1
                    items_to_show -= 1
                except StandardError:
                    # FIXME: check window size before addstr()
                    break
        self.window.overwrite(target)
        self.window.leaveok(1)


class MapApp(object):
    """ Virus World Map ncurses application """
    def __init__(self, api):
        self.api = api
        self.data = None
        self.last_fetch = 0
        self.sleep = 10  # tenths of seconds, for curses.halfdelay()
        self.polling_interval = 60

    def fetch_data(self, epoch_now, force_refresh=False):
        """ (Re)fetch data from JSON stream """
        refresh = False
        if force_refresh or self.data is None:
            refresh = True
        else:
            if self.last_fetch + self.polling_interval <= epoch_now:
                refresh = True
        
        if refresh:
            try:
                # Grab 20 banners from the main stream
                banners = []
                for banner in self.api.stream.banners():
                    if 'location' in banner and banner['location']['latitude']:
                        banners.append(banner)
                    if len(banners) >= 20:
                        break
                self.data = banners
                self.last_fetch = epoch_now
            except StandardError:
                raise
        return refresh

    def run(self, scr):
        """ Initialize and run the application """
        m = AsciiMap()
        curses.halfdelay(self.sleep)
        while True:
            now = int(time.time())
            refresh = self.fetch_data(now)
            m.set_data(self.data)
            m.draw(scr)
            scr.addstr(0, 1, 'Shodan Radar', curses.A_BOLD)
            scr.addstr(0, 40, time.strftime("%c UTC", time.gmtime(now)).rjust(37), curses.A_BOLD)

            # Key Input
            # q     - Quit
            event = scr.getch()
            if event == ord('q'):
                break

            # redraw window (to fix encoding/rendering bugs and to hide other messages to same tty)
            # user pressed 'r' or new data was fetched
            if refresh:
                m.window.redrawwin()


def launch_map(api):
    app = MapApp(api)
    return curses.wrapper(app.run)


def main(argv=None):
    """ Main function / entry point """
    from shodan import Shodan
    from shodan.cli.helpers import get_api_key

    api = Shodan(get_api_key())
    return launch_map(api)

if __name__ == '__main__':
    import sys
    sys.exit(main())
