    sed -n -E '{

    :-A1 /\/[^[:space:]]+/!{n;b-A1};
    :-A2 /^[^#]*\{/!{ /^[^#]*[#]+/{n;b-A2}; s/[[:space:]]*([\/]?[^\/]+[^[:space:]]+)[^\n]*/  \1/p;n;b-A2 };
         s/[[:space:]]*([\/]?[^\/]+[^[:space:]]+)[^\n]*/  \1/p;
    :-A3 n; /^[^#]*postrotate/{b-B2};  /^[^#]*\brotate/{H;b-B1};

    :-B1 /^[^#]*\}/{b-C1}; b-A3;
    :-B2 /^[^#]*endscript/!{n;b-B2};b-B1;

    :-C1 z;x; /\brotate/!{s/.*/  []{}\n/;p;n;b};
         s/\n[[:space:]]*(rotate[[:space:]]+[[:digit:]]+)[^\n]*/\1/;
         s/\n[[:space:]]+/  /;
         s/(.*)/  []{ \1 }\n/;p;b

    }'  logs/dnf
    

################################################################################################

target_parameter="rotate" 
new_parameter="rotate X"
n_selected_definition="3"
eregex_ignored='(postrotate|prerotate|lastaction|firstaction)'

sed -n -E '{

  :-A1 /[\/]?[^\/]+[^[:space:]]+/!{p;n;b-A1};
  :-A2 /\{/!{p;n;b-A2};
  :-A3 H;x;s/\{/&/'"$n_selected_definition"';t-B3;x
  
  :-B1 /^[^#]*endscript/!{p;n;b-B1};
  :-B2 /^[^#]*'"$eregex_ignored"'/{b-B1}; /\}/{p;b};p;n;b-B2;
  :-B3 x;b-C2;

  :-C1 /^[^#]*endscript/!{p;n;b-C1};b-C3;
  :-C2 /^[^#]*'"$eregex_ignored"'/{b-C1}; /^[^#]*\b'"$target_parameter"'/{b-D1};
  :-C3 /\}/{b-D3};p;n;b-C2;

  :-D1 s/^([[:space:]]*)\b'"$target_parameter"'[[:space:]]+[[:digit:]]+/\1'"$new_parameter"'/;
  :-D2 /^[[:space:]]*$/{n;b-C2}; /\}/{b-C3};p;n;b-C2;
  :-D3 p;n;b-D3

}' logs/dnf




## file ###
##############################3
    /var/log/hawkey.log {
    missingok
    notifempty
    rotate 1
    weekly
    create
    postrotate
     /sample/
    endscript
}


/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
{
    missingok
    weekly
    sharedscripts
    postrotate
      /sample/
    endscript
}


/var/log/dnf.log {

    missingok
    notifempty
    rotate 9
#    rotate 4
    weekly
    create
    postrotate
     /sample/
    endscript
}

    
    
