#!/usr/bin/env bash
# Blind-spot auditor v2: real-code frequency per corpus + whether the idiom's identifier
# is defined either in a Models-as-Data file OR directly in a QL query/security library.
set -u
C=/home/user/sources/code; T3=/home/user/sources/typo3/typo3-core
TOOL=/home/user/sources/tools/codeql-php
MODELS="$TOOL/php/ql/lib/ext"; QLSRC="$TOOL/php/ql/src $TOOL/php/ql/lib/codeql/php/security $TOOL/php/ql/lib/codeql/php/Concepts.qll"
OUT=/home/user/sources/tools/coverage_audit.csv
declare -A CORPUS=(
  [wordpress]="$C/wordpress-7.0.2 $C/wordpress-plugins"
  [prestashop]="$C/prestashop-9.1.4 $C/prestashop-modules"
  [typo3]="$T3 $C/typo3-extensions"
  [drupal]="$C/drupal-11.4.4 $C/drupal-modules"
  [joomla]="$C/joomla-6.1.2 $C/joomla-extensions"
  [magento]="$C/php-apps/magento_magento2"
)
# label ; ERE (using [(] not \( ) ; identifier ; category
IDIOMS=(
"Db->execute(raw SQL);->execute[(];execute;sql"
"->executeS();->executeS[(];executeS;sql"
"mysqli_query;mysqli_query[(];mysqli_query;sql"
"add_query_arg;add_query_arg[(];add_query_arg;xss-src"
"->getParam();->getParam[(];getParam;source"
"GeneralUtility::_GP;GeneralUtility::_GP[(];_GP;source"
"Tools::getValue;Tools::getValue[(];getValue;source"
"shell_exec;shell_exec[(];shell_exec;rce"
"proc_open;proc_open[(];proc_open;rce"
"->redirect();->redirect[(];redirect;redirect"
"unserialize;[^_]unserialize[(];unserialize;deser"
"dynamic include;include[ (]+[\$(];include;lfi"
"dynamic require;require[ (]+[\$(];require;lfi"
"echo (XSS sink);echo[ (]+[\$];echo;xss-sink"
"call_user_func;call_user_func[(];call_user_func;rce"
)
echo "idiom,category,in_models,in_ql_queries,wordpress,prestashop,typo3,drupal,joomla,magento" > "$OUT"
for row in "${IDIOMS[@]}"; do
  IFS=';' read -r label rx ident cat <<< "$row"
  m=$(grep -rl "\"$ident\"" $MODELS/*.model.yml 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ')
  q=$(grep -rlwi "$ident" $QLSRC 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ')
  [ -z "$m" ] && m="-"; [ -z "$q" ] && q="-"
  line="\"$label\",$cat,\"$m\",\"$q\""
  for cms in wordpress prestashop typo3 drupal joomla magento; do
    n=$(grep -rhoE "$rx" ${CORPUS[$cms]} --include=*.php 2>/dev/null | wc -l)
    line="$line,$n"
  done
  echo "$line" >> "$OUT"
done
echo DONE
