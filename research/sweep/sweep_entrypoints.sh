#!/usr/bin/env bash
# Extract concrete unauthenticated entry points from the plugin corpora.
set -u
CODE=/home/user/sources/code
OUT=/home/user/keycloak-version-detector/research/sweep

############ PrestaShop: module + core front controllers ############
PS="$OUT/prestashop_front_controllers.csv"
echo "source,module,controller_param,auth_required,ajax,file" > "$PS"
sweep_ps(){ # $1=root $2=source-label $3=module-label-mode
  find "$1" -type f -path '*/controllers/front/*.php' ! -name 'index.php' 2>/dev/null | while read -r f; do
    mod=$(echo "$f" | sed -nE 's#.*/prestashop-modules/([^/]+)/.*#\1#p'); [ -z "$mod" ] && mod="$3"
    ctrl=$(basename "$f" .php | tr 'A-Z' 'a-z')
    auth=$(grep -oiE 'public[[:space:]]+\$auth[[:space:]]*=[[:space:]]*(true|false)' "$f" | grep -oiE '(true|false)$' | head -1); [ -z "$auth" ] && auth="unset(false)"
    ajax=$(grep -qiE 'ajaxProcess|displayAjax|\$ajax[[:space:]]*=' "$f" && echo yes || echo no)
    rel=$(echo "$f" | sed "s#$CODE/##")
    echo "$2,$mod,$ctrl,$auth,$ajax,$rel" >> "$PS"
  done
}
sweep_ps "$CODE/prestashop-modules" module ""
# core front controllers
find "$CODE/prestashop-9.1.4/controllers/front" -maxdepth 1 -name '*.php' ! -name 'index.php' 2>/dev/null | while read -r f; do
  ctrl=$(basename "$f" .php | tr 'A-Z' 'a-z')
  auth=$(grep -oiE 'public[[:space:]]+\$auth[[:space:]]*=[[:space:]]*(true|false)' "$f" | grep -oiE '(true|false)$' | head -1); [ -z "$auth" ] && auth="unset(false)"
  ajax=$(grep -qiE 'ajaxProcess|displayAjax' "$f" && echo yes || echo no)
  echo "core,PrestaShop,$ctrl,$auth,$ajax,$(echo "$f"|sed "s#$CODE/##")" >> "$PS"
done

############ TYPO3: eID / middlewares / FE plugins ############
T3="$OUT/typo3_entrypoints.csv"
echo "extension,type,identifier,file" > "$T3"
for ext in "$CODE"/typo3-extensions/*/; do
  e=$(basename "$ext")
  # eID handlers (pre-auth)
  grep -rhoP "eID_include'\]\s*\[\s*'?\K[^']+" "$ext" 2>/dev/null | sort -u | while read -r k; do
    echo "$e,eID,$k,$(grep -rlP "eID_include'\]\s*\[\s*'?$k" "$ext" 2>/dev/null | head -1 | sed "s#$CODE/##")" >> "$T3"; done
  # request middlewares
  find "$ext" -name RequestMiddlewares.php 2>/dev/null | while read -r m; do
    grep -oP "'\K[a-z0-9/_-]+/[a-z0-9/_-]+(?='\s*=>)" "$m" 2>/dev/null | sort -u | while read -r id; do
      echo "$e,middleware,$id,$(echo "$m"|sed "s#$CODE/##")" >> "$T3"; done; done
  # FE extbase plugins (registerPlugin / configurePlugin -> controller::action reachable pre-auth)
  grep -rhoP "configurePlugin\(\s*'?[^,']+'?,\s*'?\K[A-Za-z0-9_]+" "$ext" 2>/dev/null | sort -u | while read -r p; do
    echo "$e,fe_plugin,$p,$(grep -rlP "configurePlugin" "$ext" 2>/dev/null|head -1|sed "s#$CODE/##")" >> "$T3"; done
  # public backend ajax routes
  find "$ext" -name 'AjaxRoutes.php' 2>/dev/null | while read -r a; do
    grep -qP "'access'\s*=>\s*'public'" "$a" && echo "$e,ajax_public,$(basename $(dirname $(dirname "$a"))),$(echo "$a"|sed "s#$CODE/##")" >> "$T3"; done
done

############ Liferay: MVC resource/action commands (in-tree modules) ############
LR="$OUT/liferay_mvc_commands.csv"
echo "module,command_type,mvc_command_name,file" > "$LR"
grep -rlE 'MVCResourceCommand|MVCActionCommand' "$CODE/liferay-2026.q2.0/modules/apps" --include=*.java 2>/dev/null | while read -r f; do
  name=$(grep -oP 'mvc\.command\.name=\K[^"\x27,}]+' "$f" 2>/dev/null | head -1)
  [ -z "$name" ] && continue
  typ=$(grep -qE 'implements.*MVCResourceCommand' "$f" && echo resource || echo action)
  mod=$(echo "$f" | sed -nE 's#.*/modules/apps/([^/]+)/.*#\1#p')
  echo "$mod,$typ,$name,$(echo "$f"|sed "s#$CODE/##")" >> "$LR"
done

echo "=== SWEEP DONE ==="
echo "PrestaShop front controllers: $(($(wc -l <"$PS")-1)) rows"
echo "  pre-auth (auth!=true):      $(awk -F, 'NR>1 && $4!="true"' "$PS" | wc -l)"
echo "TYPO3 entrypoints:            $(($(wc -l <"$T3")-1)) rows"
echo "Liferay MVC commands:         $(($(wc -l <"$LR")-1)) rows"
