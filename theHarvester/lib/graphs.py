"""
 +-------------------------------------------------------------------+
 |                   H T M L - G R A P H S   (v4.8)                  |
 |                                                                   |
 | Copyright Gerd Tentler               www.gerd-tentler.de/tools    |
 | Created: Sep. 17, 2002               Last modified: Feb. 13, 2010 |
 +-------------------------------------------------------------------+
 | This program may be used and hosted free of charge by anyone for  |
 | personal purpose as long as this copyright notice remains intact. |
 |                                                                   |
 | Obtain permission before selling the code for this program or     |
 | hosting this software on a commercial website or redistributing   |
 | this software over the Internet or in any other medium. In all    |
 | cases copyright must remain intact.                               |
 +-------------------------------------------------------------------+

=====================================================================================================
 Example:

   import graphs
   graph = graphs.BarGraph('hBar')
   graph.values = [234, 125, 289, 147, 190]
   print graph.create()

 Returns HTML code
=====================================================================================================
"""

import math
import re


class BarGraph:

    """Creates horizontal and vertical bar graphs, progress bars, and faders."""

    def __init__(self, type=''):
        #-------------------------------------------------------------------------
        # Configuration
        #-------------------------------------------------------------------------
        # graph type: "hBar", "vBar", "pBar", or "fader"
        self.type = type and type or 'hBar'
        self.values = []                          # graph data: list

        # graph background color: string
        self.graphBGColor = ''
        # graph border: string (CSS-spec: "size style color"; doesn't work with NN4)
        self.graphBorder = ''
        # graph padding: integer (pixels)
        self.graphPadding = 0

        # titles: array or string with comma-separated values
        self.titles = []
        self.titleColor = 'black'                 # title font color: string
        # title background color: string
        self.titleBGColor = '#C0E0FF'
        # title border: string (CSS specification)
        self.titleBorder = '2px groove white'
        # title font family: string (CSS specification)
        self.titleFont = 'Arial, Helvetica'
        # title font size: integer (pixels)
        self.titleSize = 12
        # title text align: "left", "center", or "right"
        self.titleAlign = 'center'
        # title padding: integer (pixels)
        self.titlePadding = 2

        # label names: list or string with comma-separated values
        self.labels = []
        self.labelColor = 'black'                 # label font color: string
        # label background color: string
        self.labelBGColor = '#C0E0FF'
        # label border: string (CSS-spec: "size style color"; doesn't work with
        # NN4)
        self.labelBorder = '2px groove white'
        # label font family: string (CSS-spec)
        self.labelFont = 'Arial, Helvetica'
        # label font size: integer (pixels)
        self.labelSize = 12
        # label text align: "left", "center", or "right"
        self.labelAlign = 'center'
        # additional space between labels: integer (pixels)
        self.labelSpace = 0

        self.barWidth = 20                        # bar width: integer (pixels)
        # bar length ratio: float (from 0.1 to 2.9)
        self.barLength = 1.0
        # bar colors OR bar images: list or string with comma-separated values
        self.barColors = []
        # bar background color: string
        self.barBGColor = ''
        # bar border: string (CSS-spec: "size style color"; doesn't work with NN4)
        self.barBorder = '2px outset white'
        # bar level colors: ascending list (bLevel, bColor[,...]); draw bars >= bLevel with bColor
        self.barLevelColors = []

        # show values: 0 = % only, 1 = abs. and %, 2 = abs. only, 3 = none
        self.showValues = 0
        # base value: integer or float (only hBar and vBar)
        self.baseValue = 0

        # abs. values font color: string
        self.absValuesColor = 'black'
        # abs. values background color: string
        self.absValuesBGColor = '#C0E0FF'
        # abs. values border: string (CSS-spec: "size style color"; doesn't work with NN4)
        self.absValuesBorder = '2px groove white'
        # abs. values font family: string (CSS-spec)
        self.absValuesFont = 'Arial, Helvetica'
        # abs. values font size: integer (pixels)
        self.absValuesSize = 12
        # abs. values prefix: string (e.g. "$")
        self.absValuesPrefix = ''
        # abs. values suffix: string (e.g. " kg")
        self.absValuesSuffix = ''

        # perc. values font color: string
        self.percValuesColor = 'black'
        # perc. values font family: string (CSS-spec)
        self.percValuesFont = 'Arial, Helvetica'
        # perc. values font size: integer (pixels)
        self.percValuesSize = 12
        # perc. values number of decimals: integer
        self.percValuesDecimals = 0

        self.charts = 1                           # number of charts: integer

        # hBar/vBar only:
        # legend items: list or string with comma-separated values
        self.legend = []
        self.legendColor = 'black'                # legend font color: string
        # legend background color: string
        self.legendBGColor = '#F0F0F0'
        # legend border: string (CSS-spec: "size style color"; doesn't work with NN4)
        self.legendBorder = '2px groove white'
        # legend font family: string (CSS-spec)
        self.legendFont = 'Arial, Helvetica'
        # legend font size: integer (pixels)
        self.legendSize = 12
        # legend vertical align: "top", "center", "bottom"
        self.legendAlign = 'top'

        # debug mode: 0 = off, 1 = on; just views some extra information
        self.debug = 0
    #-------------------------------------------------------------------------

    # Default bar colors; only used if barColors isn't set.
    __colors = (
        '#0000FF',
        '#FF0000',
        '#00E000',
        '#A0A0FF',
        '#FFA0A0',
        '#00A000')

    # Error messages.
    __err_type = 'ERROR: Type must be "hBar", "vBar", "pBar", or "fader"'

    # CSS names (don't change).
    __cssGRAPH = ''
    __cssBAR = ''
    __cssBARBG = ''
    __cssTITLE = ''
    __cssLABEL = ''
    __cssLABELBG = ''
    __cssLEGEND = ''
    __cssLEGENDBG = ''
    __cssABSVALUES = ''
    __cssPERCVALUES = ''

    # Search pattern for images.
    __img_pattern = re.compile(r'\.(jpg|jpeg|jpe|gif|png)')

    def set_styles(self):
        """set graph styles"""
        if self.graphBGColor:
            self.__cssGRAPH += 'background-color:' + self.graphBGColor + ';'
        if self.graphBorder:
            self.__cssGRAPH += 'border:' + self.graphBorder + ';'
        if self.barBorder:
            self.__cssBAR += 'border:' + self.barBorder + ';'
        if self.barBGColor:
            self.__cssBARBG += 'background-color:' + self.barBGColor + ';'
        if self.titleColor:
            self.__cssTITLE += 'color:' + self.titleColor + ';'
        if self.titleBGColor:
            self.__cssTITLE += 'background-color:' + self.titleBGColor + ';'
        if self.titleBorder:
            self.__cssTITLE += 'border:' + self.titleBorder + ';'
        if self.titleFont:
            self.__cssTITLE += 'font-family:' + self.titleFont + ';'
        if self.titleAlign:
            self.__cssTITLE += 'text-align:' + self.titleAlign + ';'
        if self.titleSize:
            self.__cssTITLE += 'font-size:' + str(self.titleSize) + 'px;'
        if self.titleBGColor:
            self.__cssTITLE += 'background-color:' + self.titleBGColor + ';'
        if self.titlePadding:
            self.__cssTITLE += 'padding:' + str(self.titlePadding) + 'px;'
        if self.labelColor:
            self.__cssLABEL += 'color:' + self.labelColor + ';'
        if self.labelBGColor:
            self.__cssLABEL += 'background-color:' + self.labelBGColor + ';'
        if self.labelBorder:
            self.__cssLABEL += 'border:' + self.labelBorder + ';'
        if self.labelFont:
            self.__cssLABEL += 'font-family:' + self.labelFont + ';'
        if self.labelSize:
            self.__cssLABEL += 'font-size:' + str(self.labelSize) + 'px;'
        if self.labelAlign:
            self.__cssLABEL += 'text-align:' + self.labelAlign + ';'
        if self.labelBGColor:
            self.__cssLABELBG += 'background-color:' + self.labelBGColor + ';'
        if self.legendColor:
            self.__cssLEGEND += 'color:' + self.legendColor + ';'
        if self.legendFont:
            self.__cssLEGEND += 'font-family:' + self.legendFont + ';'
        if self.legendSize:
            self.__cssLEGEND += 'font-size:' + str(self.legendSize) + 'px;'
        if self.legendBGColor:
            self.__cssLEGENDBG += 'background-color:' + self.legendBGColor + ';'
        if self.legendBorder:
            self.__cssLEGENDBG += 'border:' + self.legendBorder + ';'
        if self.absValuesColor:
            self.__cssABSVALUES += 'color:' + self.absValuesColor + ';'
        if self.absValuesBGColor:
            self.__cssABSVALUES += 'background-color:' + self.absValuesBGColor + ';'
        if self.absValuesBorder:
            self.__cssABSVALUES += 'border:' + self.absValuesBorder + ';'
        if self.absValuesFont:
            self.__cssABSVALUES += 'font-family:' + self.absValuesFont + ';'
        if self.absValuesSize:
            self.__cssABSVALUES += 'font-size:' + str(self.absValuesSize) + 'px;'
        if self.percValuesColor:
            self.__cssPERCVALUES += 'color:' + self.percValuesColor + ';'
        if self.percValuesFont:
            self.__cssPERCVALUES += 'font-family:' + self.percValuesFont + ';'
        if self.percValuesSize:
            self.__cssPERCVALUES += 'font-size:' + str(self.percValuesSize) + 'px;'

    def level_color(self, value, color):
        """return bar color for each level"""
        if self.barLevelColors:
            for i in range(0, len(self.barLevelColors), 2):
                try:
                    if (self.barLevelColors[i] > 0 and value >= self.barLevelColors[i]) or \
                            (self.barLevelColors[i] < 0 and value <= self.barLevelColors[i]):
                        color = self.barLevelColors[i + 1]
                except IndexError:
                    pass
        return color

    def build_bar(self, value, width, height, color):
        """return a single bar"""
        title = self.absValuesPrefix + str(value) + self.absValuesSuffix
        bg = self.__img_pattern.search(color) and 'background' or 'bgcolor'
        bar = '<table border=0 cellspacing=0 cellpadding=0><tr>'
        bar += '<td style="' + self.__cssBAR + '" ' + bg + '="' + color + '"'
        bar += (value != '') and ' title="' + title + '">' or '>'
        bar += '<div style="width:' + str(width) + 'px; height:' + str(height) + 'px;'
        bar += ' line-height:1px; font-size:1px;"></div>'
        bar += '</td></tr></table>'
        return bar

    def build_fader(self, value, width, height, x, color):
        """return a single fader"""
        fader = '<table border=0 cellspacing=0 cellpadding=0><tr>'
        x -= int(round(width / 2))
        if x > 0:
            fader += '<td width=' + str(x) + '></td>'
        fader += '<td>' + self.build_bar(value, width, height, color) + '</td>'
        fader += '</tr></table>'
        return fader

    def build_value(self, val, max_dec, sum=0, align=''):
        """return a single bar/fader value"""
        val = _number_format(val, max_dec)
        if sum:
            sum = _number_format(sum, max_dec)
        value = '<td style="' + self.__cssABSVALUES + '"'
        if align:
            value += ' align=' + align
        value += ' nowrap>'
        value += '&nbsp;' + self.absValuesPrefix + str(val) + self.absValuesSuffix
        if sum:
            value += ' / ' + self.absValuesPrefix + str(sum) + self.absValuesSuffix
        value += '&nbsp;</td>'
        return value

    def build_legend(self, barColors):
        """return the legend"""
        if hasattr(self.legend, 'split'):
            self.legend = self.legend.split(',')
        legend = '<table border=0 cellspacing=0 cellpadding=0><tr>'
        legend += '<td style="' + self.__cssLEGENDBG + '">'
        legend += '<table border=0 cellspacing=4 cellpadding=0>'
        i = 0

        for color in barColors:
            if len(self.legend) >= i + 1:
                text = hasattr(
                    self.legend[i],
                    'strip') and self.legend[i].strip() or str(self.legend[i])
            else:
                text = ''
            legend += '<tr>'
            legend += '<td>' + \
                      self.build_bar(
                          '',
                          self.barWidth,
                          self.barWidth,
                          color) + '</td>'
            legend += '<td style="' + self.__cssLEGEND + '" nowrap>' + text + '</td>'
            legend += '</tr>'
            i += 1

        legend += '</table></td></tr></table>'
        return legend

    def build_hTitle(self, titleLabel, titleValue, titleBar):
        """return horizontal titles"""
        title = '<tr>'
        title += '<td style="' + self.__cssTITLE + '">' + titleLabel + '</td>'
        if titleValue != '':
            title += '<td style="' + self.__cssTITLE + \
                     '">' + titleValue + '</td>'
        title += '<td style="' + self.__cssTITLE + '">' + titleBar + '</td>'
        title += '</tr>'
        return title

    def create_hBar(self, value, percent, mPerc, mPerc_neg,
                    max_neg, mul, valSpace, bColor, border, spacer, spacer_neg):
        """return a single horizontal bar with label and values (abs./perc.)"""
        bar = '<table border=0 cellspacing=0 cellpadding=0 height=100%><tr>'

        if percent < 0:
            percent *= -1
            bar += '<td style="' + self.__cssLABELBG + '" height=' + \
                   str(self.barWidth) + ' width=' + \
                   str(int(round((mPerc_neg - percent) * mul + valSpace))) + \
                   ' align=right nowrap>'
            if self.showValues < 2:
                bar += '<span style="' + self.__cssPERCVALUES + '">' + \
                       str(_number_format(percent, self.percValuesDecimals)) + '%</span>'
            bar += '&nbsp;</td><td style="' + self.__cssLABELBG + '">'
            bar += self.build_bar(value, int(round(percent * mul)), self.barWidth, bColor)
            bar += '</td><td width=' + str(spacer) + '></td>'
        else:
            if max_neg:
                bar += '<td style="' + self.__cssLABELBG + '" width=' + str(spacer_neg) + '>'
                bar += '<table border=0 cellspacing=0 cellpadding=0><tr><td></td></tr></table></td>'
            if percent:
                bar += '<td>'
                bar += self.build_bar(value, int(round(percent * mul)), self.barWidth, bColor)
                bar += '</td>'
            else:
                bar += '<td width=1 height=' + str(self.barWidth + (border * 2)) + '></td>'
            bar += '<td style="' + self.__cssPERCVALUES + '" width=' + \
                   str(int(round((mPerc - percent) * mul + valSpace))) + ' align=left nowrap>'
            if self.showValues < 2:
                bar += '&nbsp;' + str(_number_format(percent, self.percValuesDecimals)) + '%'
            bar += '&nbsp;</td>'

        bar += '</tr></table>'
        return bar

    def create_vBar(self, value, percent, mPerc, mPerc_neg,
                    max_neg, mul, valSpace, bColor, border, spacer, spacer_neg):
        """return a single vertical bar with label and values (abs./perc.)"""
        bar = '<table border=0 cellspacing=0 cellpadding=0 width=100%><tr align=center>'

        if percent < 0:
            percent *= -1
            bar += '<td height=' + \
                   str(spacer) + '></td></tr><tr align=center valign=top><td style="' + \
                   self.__cssLABELBG + '">'
            bar += self.build_bar(value, self.barWidth, int(round(percent * mul)), bColor)
            bar += '</td></tr><tr align=center valign=top>'
            bar += '<td style="' + self.__cssLABELBG + '" height=' + \
                   str(int(round((mPerc_neg - percent) * mul + valSpace))) + ' nowrap>'
            bar += (self.showValues < 2) and '<span style="' + self.__cssPERCVALUES + '">' + \
                   str(_number_format(percent, self.percValuesDecimals)) + \
                   '%</span>' or '&nbsp;'
            bar += '</td>'
        else:
            bar += '<td style="' + self.__cssPERCVALUES + '" valign=bottom height=' + \
                   str(int(round((mPerc - percent) * mul + valSpace))) + ' nowrap>'
            if self.showValues < 2:
                bar += str(_number_format(percent, self.percValuesDecimals)) + '%'
            bar += '</td>'
            if percent:
                bar += '</tr><tr align=center valign=bottom><td>'
                bar += self.build_bar(value, self.barWidth, int(round(percent * mul)), bColor)
                bar += '</td>'
            else:
                bar += '</tr><tr><td width=' + \
                       str(self.barWidth + (border * 2)) + ' height=1></td>'
            if max_neg:
                bar += '</tr><tr><td style="' + self.__cssLABELBG + \
                       '" height=' + str(spacer_neg) + '>'
                bar += '<table border=0 cellspacing=0 cellpadding=0><tr><td></td></tr></table></td>'

        bar += '</tr></table>'
        return bar

    def create(self):
        """create a complete bar graph (horizontal, vertical, progress, or fader)"""
        self.type = self.type.lower()
        d = self.values
        t = hasattr(
            self.titles,
            'split') and self.titles.split(
            ',') or self.titles
        r = hasattr(
            self.labels,
            'split') and self.labels.split(
            ',') or self.labels
        drc = hasattr(
            self.barColors,
            'split') and self.barColors.split(
            ',') or self.barColors
        val = []
        bc = []
        if self.barLength < 0.1:
            self.barLength = 0.1
        elif self.barLength > 2.9:
            self.barLength = 2.9
        labels = (len(d) > len(r)) and len(d) or len(r)

        if self.type == 'pbar' or self.type == 'fader':
            if not self.barBGColor:
                self.barBGColor = self.labelBGColor
            if self.labelBGColor == self.barBGColor and len(t) == 0:
                self.labelBGColor = ''
                self.labelBorder = ''

        self.set_styles()

        graph = '<table border=0 cellspacing=0 cellpadding=' + \
                str(self.graphPadding) + '><tr>'
        graph += '<td' + \
                 (self.__cssGRAPH and ' style="' +
                  self.__cssGRAPH + '"' or '') + '>'

        if self.legend and self.type != 'pbar' and self.type != 'fader':
            graph += '<table border=0 cellspacing=0 cellpadding=0><tr><td>'

        if self.charts > 1:
            divide = math.ceil(labels / self.charts)
            graph += '<table border=0 cellspacing=0 cellpadding=6><tr valign=top><td>'
        else:
            divide = 0

        sum = 0
        max = 0
        max_neg = 0
        max_dec = 0
        ccnt = 0
        lcnt = 0
        chart = 0

        for i in range(labels):
            if divide and i and not i % divide:
                lcnt = 0
                chart += 1

            try:
                drv = len(d[i]) and [e for e in d[i]] or [d[i]]
            except:
                drv = [d[i]]

            j = 0
            dec = 0
            if len(val) <= chart:
                val.append([])

            for v in drv:
                s = str(v)
                if s.find('.') != -1:
                    dec = len(s[s.find('.') + 1:])
                    if dec > max_dec:
                        max_dec = dec

                if len(val[chart]) <= lcnt:
                    val[chart].append([])
                val[chart][lcnt].append(v)

                if v != 0:
                    v -= self.baseValue

                if v > max:
                    max = v
                elif v < max_neg:
                    max_neg = v

                if v < 0:
                    v *= -1
                sum += v

                if len(bc) <= j:
                    if ccnt >= len(self.__colors):
                        ccnt = 0
                    if len(drc) <= j or len(drc[j]) < 3:
                        bc.append(self.__colors[ccnt])
                        ccnt += 1
                    else:
                        bc.append(drc[j].strip())

                j += 1

            lcnt += 1

        border = int(self.barBorder[0])
        mPerc = sum and int(round(max * 100.0 / sum)) or 0
        if self.type == 'pbar' or self.type == 'fader':
            mul = 2
        else:
            mul = mPerc and 100.0 / mPerc or 1
        mul *= self.barLength

        if self.showValues < 2:
            if self.type == 'hbar':
                valSpace = (self.percValuesDecimals * (self.percValuesSize / 1.6)) + \
                           (self.percValuesSize * 3.2)
            else:
                valSpace = self.percValuesSize * 1.2
        else:
            valSpace = self.percValuesSize
        spacer = maxSize = int(round(mPerc * mul + valSpace + border * 2))

        if max_neg:
            mPerc_neg = sum and int(round(-max_neg * 100.0 / sum)) or 0
            if mPerc_neg > mPerc and self.type != 'pbar' and self.type != 'fader':
                mul = 100.0 / mPerc_neg * self.barLength
            spacer_neg = int(round(mPerc_neg * mul + valSpace + border * 2))
            maxSize += spacer_neg
        else:
            mPerc_neg = spacer_neg = 0

        titleLabel = ''
        titleValue = ''
        titleBar = ''

        if len(t) > 0:
            titleLabel = (t[0] == '') and '&nbsp;' or t[0]

            if self.showValues == 1 or self.showValues == 2:
                titleValue = (t[1] == '') and '&nbsp;' or t[1]
                titleBar = (t[2] == '') and '&nbsp;' or t[2]
            else:
                titleBar = (t[1] == '') and '&nbsp;' or t[1]

        chart = 0
        lcnt = 0

        for v in val:
            graph += '<table border=0 cellspacing=2 cellpadding=0>'

            if self.type == 'hbar':
                if len(t) > 0:
                    graph += self.build_hTitle(titleLabel, titleValue, titleBar)

                for i in range(len(v)):
                    label = (
                                    lcnt < len(r)) and r[lcnt].strip() or str(lcnt + 1)
                    rowspan = len(v[i])
                    graph += '<tr><td style="' + self.__cssLABEL + '"' + \
                             ((rowspan > 1) and ' rowspan=' + str(rowspan) or '') + '>'
                    graph += '&nbsp;' + label + '&nbsp;</td>'

                    for j in range(len(v[i])):
                        value = v[i][j] and v[i][j] - self.baseValue or 0
                        percent = sum and value * 100.0 / sum or 0
                        value = _number_format(v[i][j], max_dec)
                        bColor = self.level_color(v[i][j], bc[j])

                        if self.showValues == 1 or self.showValues == 2:
                            graph += self.build_value(v[i]
                                                      [j], max_dec, 0, 'right')

                        graph += '<td' + (self.__cssBARBG and ' style="' + self.__cssBARBG + '"' or '') + \
                                 ' height=100% width=' + \
                                 str(maxSize) + '>'
                        graph += self.create_hBar(
                            value, percent, mPerc, mPerc_neg,
                            max_neg, mul, valSpace, bColor, border, spacer, spacer_neg)
                        graph += '</td></tr>'
                        if j < len(v[i]) - 1:
                            graph += '<tr>'

                    if self.labelSpace and i < len(v) - 1:
                        graph += '<tr><td colspan=3 height=' + \
                                 str(self.labelSpace) + '></td></tr>'
                    lcnt += 1

            elif self.type == 'vbar':
                graph += '<tr align=center valign=bottom>'

                if titleBar != '':
                    titleBar = titleBar.replace('-', '-<br>')
                    graph += '<td style="' + self.__cssTITLE + '" valign=middle>' + titleBar + '</td>'

                for i in range(len(v)):
                    for j in range(len(v[i])):
                        value = v[i][j] and v[i][j] - self.baseValue or 0
                        percent = sum and value * 100.0 / sum or 0
                        value = _number_format(v[i][j], max_dec)
                        bColor = self.level_color(v[i][j], bc[j])

                        graph += '<td' + \
                                 (self.__cssBARBG and ' style="' +
                                  self.__cssBARBG + '"' or '') + '>'
                        graph += self.create_vBar(
                            value, percent, mPerc, mPerc_neg,
                            max_neg, mul, valSpace, bColor, border, spacer, spacer_neg)
                        graph += '</td>'

                    if self.labelSpace:
                        graph += '<td width=' + str(self.labelSpace) + '></td>'

                if self.showValues == 1 or self.showValues == 2:
                    graph += '</tr><tr align=center>'
                    if titleValue != '':
                        graph += '<td style="' + self.__cssTITLE + \
                                 '">' + titleValue + '</td>'

                    for i in range(len(v)):
                        for j in range(len(v[i])):
                            graph += self.build_value(v[i][j], max_dec)
                        if self.labelSpace:
                            graph += '<td width=' + str(self.labelSpace) + '></td>'

                graph += '</tr><tr>'
                if titleLabel != '':
                    graph += '<td style="' + self.__cssTITLE + '">' + titleLabel + '</td>'

                for i in range(len(v)):
                    label = (
                                    lcnt < len(r)) and r[lcnt].strip() or str(lcnt + 1)
                    colspan = len(v[i])
                    graph += '<td style="' + self.__cssLABEL + '"' + \
                             ((colspan > 1) and ' colspan=' + str(colspan) or '') + '>'
                    graph += '&nbsp;' + label + '&nbsp;</td>'
                    if self.labelSpace:
                        graph += '<td width=' + str(self.labelSpace) + '></td>'
                    lcnt += 1

                graph += '</tr>'

            elif self.type == 'pbar' or self.type == 'fader':
                if len(t) > 0:
                    graph += self.build_hTitle(titleLabel, titleValue, titleBar)

                for i in range(len(v)):
                    try:
                        m = (len(v[i]) > 1) and True or False
                    except:
                        m = False

                    if m or not i:
                        label = (
                                        lcnt < len(r)) and r[lcnt].strip() or str(i + 1)
                        graph += '<tr>'

                        if len(r):
                            graph += '<td style="' + self.__cssLABEL + '">'
                            graph += '&nbsp;' + label + '&nbsp;</td>'

                        try:
                            sum = v[i][1] and v[i][1] or v[-1][0]
                        except:
                            sum = v[-1][0]

                        percent = sum and v[i][0] * 100.0 / sum or 0
                        value = _number_format(v[i][0], max_dec)

                        if self.showValues == 1 or self.showValues == 2:
                            graph += self.build_value(v[i]
                                                      [0], max_dec, sum, 'right')

                        graph += '<td' + \
                                 (self.__cssBARBG and ' style="' +
                                  self.__cssBARBG + '"' or '') + '>'

                        self.barColors = (
                                                 len(drc) >= i + 1) and drc[i].strip() or self.__colors[0]
                        bColor = self.level_color(v[i][0], self.barColors)
                        graph += '<table border=0 cellspacing=0 cellpadding=0><tr><td>'
                        if self.type == 'fader':
                            graph += self.build_fader(
                                value, int(round(self.barWidth / 2)),
                                self.barWidth, int(round(percent * mul)), bColor)
                        else:
                            graph += self.build_bar(value,
                                                    int(round(percent * mul)), self.barWidth, bColor)
                        graph += '</td><td width=' + \
                                 str(int(round((100 - percent) * mul))) + '></td>'
                        graph += '</tr></table></td>'
                        if self.showValues < 2:
                            graph += '<td style="' + self.__cssPERCVALUES + '" nowrap>&nbsp;' + \
                                     str(_number_format(percent, self.percValuesDecimals)) + '%</td>'
                        graph += '</tr>'
                        if self.labelSpace and i < len(v) - 1:
                            graph += '<td colspan=3 height=' + \
                                     str(self.labelSpace) + '></td>'
                        lcnt += 1

            else:
                graph += '<tr><td>' + self.__err_type + '</td></tr>'

            graph += '</table>'

            if chart < self.charts - 1 and len(val[chart + 1]):
                graph += '</td>'
                if self.type == 'vbar':
                    graph += '</tr><tr valign=top>'
                graph += '<td>'

            chart += 1

        if self.charts > 1:
            graph += '</td></tr></table>'

        if self.legend and self.type != 'pbar' and self.type != 'fader':
            graph += '</td><td width=10>&nbsp;</td><td' + \
                     (self.legendAlign and ' valign=' + self.legendAlign or '') + '>'
            graph += self.build_legend(bc)
            graph += '</td></tr></table>'

        if self.debug:
            graph += "<br>sum=%s max=%s max_neg=%s max_dec=%s " % (sum, max, max_neg, max_dec)
            graph += "mPerc=%s mPerc_neg=%s mul=%s valSpace=%s" % (mPerc, mPerc_neg, mul, valSpace)

        graph += '</td></tr></table>'
        return graph


def _number_format(val, dec):
    """return float with dec decimals; if dec is 0, return integer"""
    return dec and ('%.' + str(dec) + 'f') % val or int(round(val))


if __name__ == '__main__':
    print(__doc__)
