#!/bin/bash

# Configuration
BASE_URL="https://controller"
COOKIE_FILE="session_cookies.txt"
WGET_OPTS="--no-check-certificate -nv -O- --keep-session-cookies --content-on-error"

# Helper function to print usage
usage() {
    echo "Usage: $0 <command> [arguments]"
    echo ""
    echo "Authentication:"
    echo "  login <username> <password>"
    echo "  logout"
    echo "  me"
    echo "  update-password <old_password> <new_password>"
    echo ""
    echo "User Dashboard:"
    echo "  my-services"
    echo "  my-active"
    echo "  select-service <service_id>"
    echo "  deselect-service <service_id>"
    echo ""
    echo "Admin - Users:"
    echo "  list-users"
    echo "  create-user <username> <password> <role_id>"
    echo "  delete-user <user_id>"
    echo "  update-user-role <user_id> <role_id>"
    echo "  reset-user-pwd <user_id> <new_password>"
    echo "  user-services <user_id>"
    echo "  add-user-service <user_id> <service_id>"
    echo "  del-user-service <user_id> <service_id>"
    echo ""
    echo "Admin - Roles:"
    echo "  list-roles"
    echo "  create-role <name> <description>"
    echo "  delete-role <role_id>"
    echo "  role-services <role_id>"
    echo "  add-role-service <role_id> <service_id>"
    echo "  del-role-service <role_id> <service_id>"
    echo ""
    echo "Admin - Services:"
    echo "  list-services"
    echo "  create-service <name> <hostname:port> <description>"
    echo "  update-service <id> <name> <hostname:port> <description>"
    echo "  delete-service <id>"
    exit 1
}

# Check if command is provided
if [ -z "$1" ]; then
    usage
fi

CMD="$1"
shift

# Execute command
case "$CMD" in
    # --- Authentication ---
    login)
        if [ "$#" -ne 2 ]; then echo "Usage: $0 login <username> <password>"; exit 1; fi
        wget $WGET_OPTS \
             --save-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --post-data="{\"username\": \"$1\", \"password\": \"$2\"}" \
             "$BASE_URL/api/auth/login"
        echo ""
        ;;
    logout)
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --post-data="" \
             "$BASE_URL/api/auth/logout"
        rm -f "$COOKIE_FILE"
        echo ""
        ;;
    me)
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             "$BASE_URL/api/auth/me"
        echo ""
        ;;
    update-password)
        if [ "$#" -ne 2 ]; then echo "Usage: $0 update-password <old> <new>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --post-data="{\"old_password\": \"$1\", \"new_password\": \"$2\"}" \
             "$BASE_URL/api/auth/password"
        echo ""
        ;;

    # --- User Dashboard ---
    my-services)
        wget $WGET_OPTS --load-cookies "$COOKIE_FILE" "$BASE_URL/api/me/services"
        echo ""
        ;;
    my-active)
        wget $WGET_OPTS --load-cookies "$COOKIE_FILE" "$BASE_URL/api/me/selected"
        echo ""
        ;;
    select-service)
        if [ "$#" -ne 1 ]; then echo "Usage: $0 select-service <service_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --post-data="{\"service_id\": $1}" \
             "$BASE_URL/api/me/selected"
        echo ""
        ;;
    deselect-service)
        if [ "$#" -ne 1 ]; then echo "Usage: $0 deselect-service <service_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --method=DELETE \
             "$BASE_URL/api/me/selected/$1"
        echo ""
        ;;

    # --- Admin: Users ---
    list-users)
        wget $WGET_OPTS --load-cookies "$COOKIE_FILE" "$BASE_URL/api/users"
        echo ""
        ;;
    create-user)
        if [ "$#" -ne 3 ]; then echo "Usage: $0 create-user <username> <password> <role_id>"; exit 1; fi
        # Note: Nested JSON structure required by user_handler.go
        JSON_DATA=$(printf '{"credentials": {"username": "%s", "password": "%s"}, "role_id": %s}' "$1" "$2" "$3")
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --post-data="$JSON_DATA" \
             "$BASE_URL/api/users"
        echo ""
        ;;
    delete-user)
        if [ "$#" -ne 1 ]; then echo "Usage: $0 delete-user <user_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --method=DELETE \
             "$BASE_URL/api/users/$1"
        echo ""
        ;;
    update-user-role)
        if [ "$#" -ne 2 ]; then echo "Usage: $0 update-user-role <user_id> <role_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --method=PUT \
             --body-data="{\"role_id\": $2}" \
             "$BASE_URL/api/users/$1/role"
        echo ""
        ;;
    reset-user-pwd)
        if [ "$#" -ne 2 ]; then echo "Usage: $0 reset-user-pwd <user_id> <new_password>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --post-data="{\"password\": \"$2\"}" \
             "$BASE_URL/api/users/$1/reset-password"
        echo ""
        ;;
    user-services)
        if [ "$#" -ne 1 ]; then echo "Usage: $0 user-services <user_id>"; exit 1; fi
        wget $WGET_OPTS --load-cookies "$COOKIE_FILE" "$BASE_URL/api/users/$1/services"
        echo ""
        ;;
    add-user-service)
        if [ "$#" -ne 2 ]; then echo "Usage: $0 add-user-service <user_id> <service_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --post-data="{\"service_id\": $2}" \
             "$BASE_URL/api/users/$1/services"
        echo ""
        ;;
    del-user-service)
        if [ "$#" -ne 2 ]; then echo "Usage: $0 del-user-service <user_id> <service_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --method=DELETE \
             "$BASE_URL/api/users/$1/services/$2"
        echo ""
        ;;

    # --- Admin: Roles ---
    list-roles)
        wget $WGET_OPTS --load-cookies "$COOKIE_FILE" "$BASE_URL/api/roles"
        echo ""
        ;;
    create-role)
        if [ "$#" -ne 2 ]; then echo "Usage: $0 create-role <name> <description>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --post-data="{\"name\": \"$1\", \"description\": \"$2\"}" \
             "$BASE_URL/api/roles"
        echo ""
        ;;
    delete-role)
        if [ "$#" -ne 1 ]; then echo "Usage: $0 delete-role <role_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --method=DELETE \
             "$BASE_URL/api/roles/$1"
        echo ""
        ;;
    role-services)
        if [ "$#" -ne 1 ]; then echo "Usage: $0 role-services <role_id>"; exit 1; fi
        wget $WGET_OPTS --load-cookies "$COOKIE_FILE" "$BASE_URL/api/roles/$1/services"
        echo ""
        ;;
    add-role-service)
        if [ "$#" -ne 2 ]; then echo "Usage: $0 add-role-service <role_id> <service_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --post-data="{\"service_id\": $2}" \
             "$BASE_URL/api/roles/$1/services"
        echo ""
        ;;
    del-role-service)
        if [ "$#" -ne 2 ]; then echo "Usage: $0 del-role-service <role_id> <service_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --method=DELETE \
             "$BASE_URL/api/roles/$1/services/$2"
        echo ""
        ;;

    # --- Admin: Services ---
    list-services)
        wget $WGET_OPTS --load-cookies "$COOKIE_FILE" "$BASE_URL/api/services"
        echo ""
        ;;
    create-service)
        if [ "$#" -ne 3 ]; then echo "Usage: $0 create-service <name> <hostname:port> <description>"; exit 1; fi
        JSON_DATA=$(printf '{"name": "%s", "hostname": "%s", "description": "%s"}' "$1" "$2" "$3")
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --post-data="$JSON_DATA" \
             "$BASE_URL/api/services"
        echo ""
        ;;
    update-service)
        if [ "$#" -ne 4 ]; then echo "Usage: $0 update-service <id> <name> <hostname:port> <description>"; exit 1; fi
        JSON_DATA=$(printf '{"name": "%s", "hostname": "%s", "description": "%s"}' "$2" "$3" "$4")
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --header="Content-Type: application/json" \
             --method=PUT \
             --body-data="$JSON_DATA" \
             "$BASE_URL/api/services/$1"
        echo ""
        ;;
    delete-service)
        if [ "$#" -ne 1 ]; then echo "Usage: $0 delete-service <service_id>"; exit 1; fi
        wget $WGET_OPTS \
             --load-cookies "$COOKIE_FILE" \
             --method=DELETE \
             "$BASE_URL/api/services/$1"
        echo ""
        ;;

    *)
        usage
        ;;
esac
