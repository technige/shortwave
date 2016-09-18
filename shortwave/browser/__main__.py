#!/usr/bin/env python
# coding: utf-8

from curses import wrapper, newwin, newpad, init_pair, COLOR_BLUE, COLOR_WHITE, color_pair, KEY_EXIT, \
    KEY_RESIZE, KEY_NPAGE, KEY_DOWN, KEY_PPAGE, curs_set
from curses.textpad import Textbox
from sys import argv

from shortwave.http import get


class Shell(object):

    uri = b""

    def __init__(self, window):
        self.window = window
        init_pair(1, COLOR_WHITE, COLOR_BLUE)
        self.window.bkgd(" ", color_pair(1))
        self.window.addstr(0, 0, b"GET ")
        #self.uri_pad = self.window.derwin(1, 20)

    def refresh(self):
        #self.uri_pad.refresh(0, 0, 0, 4, 1, 40)
        # self.uri_textbox = Textbox(self.uri_pad)
        self.window.refresh()


class Document(object):

    # resource metadata management
    location = None
    domain = None
    referrer = None
    cookie = None
    last_modified = None
    ready_state = None

    def __init__(self):
        self.lines = None
        self.height = None
        self.width = None
        self.view = None

    def load(self, source):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(source, 'html.parser')
        self.lines = soup.text.splitlines()
        self.height = len(self.lines)
        self.width = max(map(len, self.lines))
        self.view = newpad(self.height, self.width)
        for y, line in enumerate(self.lines):
            self.view.addstr(y, 0, line)


class TitleBar(object):

    title = None
    uri = None

    def __init__(self, window):
        self.window = window
        self.window.bkgd(" ", color_pair(1))
        self.window.refresh()

    def set_title(self, title):
        _, width = self.window.getmaxyx()
        self.window.addnstr(0, 0, title, width)
        self.window.refresh()


class BrowsingContext(object):

    def __init__(self, window):
        self.window = window
        self.documents = []
        self.active_document = -1

    def navigate(self, resource):
        document = Document()
        document.load(get(resource).content)
        self.documents.append(document)
        self.active_document += 1

    def render(self, top):
        h, w = self.window.getmaxyx()
        self.documents[self.active_document].view.refresh(top, 0, 1, 0, h - 3, w - 1)
        self.window.refresh()


class Tab(object):

    def __init__(self, window):
        self.window = window
        _, width = self.window.getmaxyx()
        self.title_bar = TitleBar(self.window.derwin(1, width, 0, 0))
        self.browsing_context = BrowsingContext(self.window)

    def navigate(self, resource):
        self.title_bar.set_title(resource.decode("iso-8859-1"))
        self.browsing_context.navigate(resource)

    def render(self, top):
        self.browsing_context.render(top)


class Browser(object):

    def __init__(self, window):
        curs_set(0)
        init_pair(1, COLOR_WHITE, COLOR_BLUE)
        self.window = window
        self.window.clear()
        self.window.refresh()
        self.tab = Tab(self.window)

    def navigate(self, resource):
        self.tab.navigate(resource)

    def render(self, top):
        self.tab.render(top)


def browser(window):
    try:
        uri = argv[1].encode("utf-8")
    except IndexError:
        uri = b"http://shortwave.tech/hello"
    b = Browser(window)
    b.navigate(uri)
    top = 0
    b.render(top)
    done = False
    while not done:
        try:
            k = b.window.getch()
        except KeyboardInterrupt:
            done = True
        else:
            if k == KEY_PPAGE:
                top -= 10
                b.render(top)
            elif k == KEY_NPAGE:
                top += 10
                b.render(top)
            elif k == KEY_RESIZE:
                b.render(top)


def main():
    wrapper(browser)


if __name__ == "__main__":
    main()


# try:
#     from tkinter import *
# except ImportError:
#     from Tkinter import *
#
#
# class Application(Frame):
#     def __init__(self, master=None):
#         Frame.__init__(self, master)
#         self.grid(sticky="nsew")
#         self.createWidgets()
#
#     def createWidgets(self):
#         top=self.winfo_toplevel()
#         top.rowconfigure(0, weight=1)
#         top.columnconfigure(0, weight=1)
#         self.rowconfigure(0, weight=1)
#         self.columnconfigure(0, weight=1)
#
#         self.toolbar = Frame(self)
#         self.method = Spinbox(self.toolbar, values=["GET", "POST", "PUT", "DELETE"])
#         self.method.grid(row=0, column=0)
#         self.target = StringVar()
#         self.target.set("http://shortwave.tech/hello")
#         self.target_entry = Entry(self.toolbar, textvariable=self.target)
#         self.target_entry.grid(row=0, column=1, sticky=E + W)
#         self.forward_button = Button(self.toolbar, text="->", command=self.forward)
#         self.forward_button.grid(row=0, column=2)
#         self.toolbar.grid(sticky=E + W)
#
#         self.content = Text(self)
#         self.content.grid(row=1, column=0)
#
#     def forward(self):
#         from shortwave.http import get
#         rs = get(self.target.get().encode("iso-8859-1"))
#         self.content.insert(END, rs.content)
#
# app = Application()
# app.master.title("Shortwave Browser")
# app.mainloop()
