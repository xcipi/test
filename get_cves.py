from ares import CVESearch

def get_cve(cveid):

    print 'Zhanam ' + cveid + ' ...'

    cve = CVESearch()

    print cve.search(cveid)

get_cve('microsoft')
