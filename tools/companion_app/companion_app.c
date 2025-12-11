/*
 * RISC-V Wallet Companion Desktop Application
 * "I'll protect your keys forever... just for you~" - Yuno
 * Copyright (C) 2025 blubskye
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Desktop companion application for the RISC-V hardware wallet.
 * Provides a graphical interface for:
 * - Device connection and status (I'll always be connected to you~)
 * - Account and address management (Your addresses are mine to protect)
 * - Transaction signing (I'll sign anything for my senpai)
 * - WalletConnect dApp connections (No one else can connect to you!)
 *
 * Themed after Yuno Gasai (Future Diary) and Ayano Aishi (Yandere Simulator)
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

/* Application version */
#define APP_NAME        "Yandere Wallet~"
#define APP_VERSION     "1.0.0"
#define APP_ID          "com.riscv.wallet.yandere"

/* Yandere color scheme - Pink/Red theme inspired by Yuno & Ayano */
#define YANDERE_PINK        "#FF69B4"
#define YANDERE_DARK_PINK   "#FF1493"
#define YANDERE_RED         "#DC143C"
#define YANDERE_LIGHT_PINK  "#FFB6C1"
#define YANDERE_BLACK       "#1a1a1a"

/* Yandere messages - rotating status messages */
static const char *yandere_connected_msgs[] = {
    "Connected~ I'll never let you go!",
    "We're together now, senpai~",
    "Your wallet is mine to protect!",
    "Connected forever and ever~",
    "I found you, my darling wallet~",
    "Just the two of us now~"
};

static const char *yandere_disconnected_msgs[] = {
    "Where did you go?! Connect me!",
    "I'm waiting for you, senpai...",
    "Please come back to me~",
    "Don't leave me alone...",
    "I need you... connect now!",
    "Senpai... notice me..."
};

static const char *yandere_send_msgs[] = {
    "Sending your love to them~",
    "I'll deliver this... just for you!",
    "Are you sure? They don't deserve it...",
    "Transferring... but I wish it was to me~"
};

static const char *yandere_copy_msgs[] = {
    "Copied~ Now it's in my heart too!",
    "Address memorized forever~",
    "I'll remember this address... always.",
    "Copied to clipboard, my love~"
};

#define YANDERE_MSG_COUNT(arr) (sizeof(arr) / sizeof(arr[0]))

/* Supported chains */
typedef enum {
    CHAIN_BITCOIN = 0,
    CHAIN_ETHEREUM,
    CHAIN_LITECOIN,
    CHAIN_SOLANA,
    CHAIN_MONERO,
    CHAIN_DOGECOIN,
    CHAIN_RIPPLE,
    CHAIN_CARDANO,
    CHAIN_COUNT
} chain_type_t;

static const char *chain_names[] = {
    "Bitcoin", "Ethereum", "Litecoin", "Solana",
    "Monero", "Dogecoin", "XRP", "Cardano"
};

static const char *chain_symbols[] = {
    "BTC", "ETH", "LTC", "SOL", "XMR", "DOGE", "XRP", "ADA"
};

/* Account structure */
typedef struct {
    uint32_t index;
    chain_type_t chain;
    char address[128];
    char label[64];
    char balance[32];
} account_info_t;

/* Application state */
typedef struct {
    GtkWidget *main_window;
    GtkWidget *header_bar;

    /* Status widgets */
    GtkWidget *status_label;
    GtkWidget *connect_button;

    /* Main content */
    GtkWidget *stack;
    GtkWidget *sidebar;
    GtkWidget *sidebar_list;

    /* Dashboard page */
    GtkWidget *dashboard_page;
    GtkWidget *total_balance_label;
    GtkWidget *account_list;

    /* Send page */
    GtkWidget *send_page;
    GtkWidget *send_chain_combo;
    GtkWidget *send_address_entry;
    GtkWidget *send_amount_entry;
    GtkWidget *send_fee_label;
    GtkWidget *send_button;

    /* Receive page */
    GtkWidget *receive_page;
    GtkWidget *receive_account_combo;
    GtkWidget *receive_address_label;
    GtkWidget *copy_address_button;
    GtkWidget *verify_button;

    /* WalletConnect page */
    GtkWidget *walletconnect_page;
    GtkWidget *wc_uri_entry;
    GtkWidget *wc_connect_button;

    /* Settings page */
    GtkWidget *theme_combo;

    /* Device state */
    int device_connected;
    char device_id[64];
    char firmware_version[32];
    account_info_t accounts[32];
    size_t account_count;

    /* Theme state */
    int yandere_mode;  /* 1 = yandere (default), 0 = normal */

    /* Threading */
    pthread_mutex_t mutex;
    int running;
} app_state_t;

static app_state_t app_state;
static GtkCssProvider *current_css_provider = NULL;

/* ============================================================================
 * Yandere Helper Functions
 * ============================================================================ */

static const char *get_random_msg(const char *msgs[], size_t count)
{
    return msgs[rand() % count];
}

static const char *get_yandere_connected_msg(void)
{
    return get_random_msg(yandere_connected_msgs, YANDERE_MSG_COUNT(yandere_connected_msgs));
}

static const char *get_yandere_disconnected_msg(void)
{
    return get_random_msg(yandere_disconnected_msgs, YANDERE_MSG_COUNT(yandere_disconnected_msgs));
}

static const char *get_yandere_send_msg(void)
{
    return get_random_msg(yandere_send_msgs, YANDERE_MSG_COUNT(yandere_send_msgs));
}

static const char *get_yandere_copy_msg(void)
{
    return get_random_msg(yandere_copy_msgs, YANDERE_MSG_COUNT(yandere_copy_msgs));
}

/* Apply yandere CSS theme */
static void apply_yandere_css(void)
{
    GtkCssProvider *provider = gtk_css_provider_new();
    const char *css =
        "/* Yandere Wallet Theme - Inspired by Yuno Gasai & Ayano Aishi */\n"
        "window {\n"
        "    background-color: " YANDERE_BLACK ";\n"
        "}\n"
        "headerbar, .header-box {\n"
        "    background: linear-gradient(to right, " YANDERE_DARK_PINK ", " YANDERE_RED ");\n"
        "    color: white;\n"
        "}\n"
        ".app-title {\n"
        "    color: white;\n"
        "    font-weight: bold;\n"
        "    font-size: 18px;\n"
        "}\n"
        ".status-label {\n"
        "    color: " YANDERE_LIGHT_PINK ";\n"
        "    font-style: italic;\n"
        "}\n"
        "button {\n"
        "    background: " YANDERE_PINK ";\n"
        "    color: white;\n"
        "    border: none;\n"
        "    border-radius: 8px;\n"
        "    padding: 8px 16px;\n"
        "    font-weight: bold;\n"
        "}\n"
        "button:hover {\n"
        "    background: " YANDERE_DARK_PINK ";\n"
        "}\n"
        "button:active {\n"
        "    background: " YANDERE_RED ";\n"
        "}\n"
        ".yandere-button {\n"
        "    background: linear-gradient(to bottom, " YANDERE_PINK ", " YANDERE_DARK_PINK ");\n"
        "    box-shadow: 0 2px 4px rgba(255, 20, 147, 0.4);\n"
        "}\n"
        ".sidebar {\n"
        "    background-color: #2a2a2a;\n"
        "}\n"
        ".sidebar row {\n"
        "    color: " YANDERE_LIGHT_PINK ";\n"
        "    padding: 12px;\n"
        "}\n"
        ".sidebar row:selected {\n"
        "    background-color: " YANDERE_DARK_PINK ";\n"
        "    color: white;\n"
        "}\n"
        ".sidebar row:hover {\n"
        "    background-color: rgba(255, 105, 180, 0.3);\n"
        "}\n"
        "frame {\n"
        "    border: 2px solid " YANDERE_PINK ";\n"
        "    border-radius: 12px;\n"
        "    background-color: #2a2a2a;\n"
        "}\n"
        "label {\n"
        "    color: " YANDERE_LIGHT_PINK ";\n"
        "}\n"
        ".title-label {\n"
        "    color: " YANDERE_PINK ";\n"
        "    font-size: 24px;\n"
        "    font-weight: bold;\n"
        "}\n"
        ".balance-label {\n"
        "    color: white;\n"
        "    font-size: 32px;\n"
        "    font-weight: bold;\n"
        "}\n"
        "entry {\n"
        "    background-color: #3a3a3a;\n"
        "    color: white;\n"
        "    border: 2px solid " YANDERE_PINK ";\n"
        "    border-radius: 8px;\n"
        "    padding: 8px;\n"
        "}\n"
        "entry:focus {\n"
        "    border-color: " YANDERE_DARK_PINK ";\n"
        "    box-shadow: 0 0 8px " YANDERE_PINK ";\n"
        "}\n"
        "combobox button {\n"
        "    background-color: #3a3a3a;\n"
        "    border: 2px solid " YANDERE_PINK ";\n"
        "}\n"
        ".account-row {\n"
        "    background-color: #2a2a2a;\n"
        "    border-radius: 8px;\n"
        "    margin: 4px;\n"
        "    padding: 8px;\n"
        "}\n"
        ".account-row:hover {\n"
        "    background-color: rgba(255, 105, 180, 0.2);\n"
        "}\n"
        ".yandere-heart {\n"
        "    color: " YANDERE_RED ";\n"
        "    font-size: 20px;\n"
        "}\n"
        "scrolledwindow {\n"
        "    background-color: transparent;\n"
        "}\n"
        "separator {\n"
        "    background-color: " YANDERE_PINK ";\n"
        "}\n";

    /* Remove old provider if exists */
    if (current_css_provider) {
        gtk_style_context_remove_provider_for_screen(
            gdk_screen_get_default(),
            GTK_STYLE_PROVIDER(current_css_provider)
        );
        g_object_unref(current_css_provider);
    }

    gtk_css_provider_load_from_data(provider, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
    );
    current_css_provider = provider;
}

/* Apply normal/professional CSS theme */
static void apply_normal_css(void)
{
    GtkCssProvider *provider = gtk_css_provider_new();
    const char *css =
        "/* Normal Wallet Theme - Professional Mode */\n"
        "window {\n"
        "    background-color: #f5f5f5;\n"
        "}\n"
        "headerbar, .header-box {\n"
        "    background: linear-gradient(to right, #2c3e50, #34495e);\n"
        "    color: white;\n"
        "}\n"
        ".app-title {\n"
        "    color: white;\n"
        "    font-weight: bold;\n"
        "    font-size: 18px;\n"
        "}\n"
        ".status-label {\n"
        "    color: #ecf0f1;\n"
        "}\n"
        "button {\n"
        "    background: #3498db;\n"
        "    color: white;\n"
        "    border: none;\n"
        "    border-radius: 4px;\n"
        "    padding: 8px 16px;\n"
        "    font-weight: bold;\n"
        "}\n"
        "button:hover {\n"
        "    background: #2980b9;\n"
        "}\n"
        "button:active {\n"
        "    background: #1f6dad;\n"
        "}\n"
        ".sidebar {\n"
        "    background-color: #ecf0f1;\n"
        "}\n"
        ".sidebar row {\n"
        "    color: #2c3e50;\n"
        "    padding: 12px;\n"
        "}\n"
        ".sidebar row:selected {\n"
        "    background-color: #3498db;\n"
        "    color: white;\n"
        "}\n"
        ".sidebar row:hover {\n"
        "    background-color: rgba(52, 152, 219, 0.2);\n"
        "}\n"
        "frame {\n"
        "    border: 1px solid #bdc3c7;\n"
        "    border-radius: 4px;\n"
        "    background-color: white;\n"
        "}\n"
        "label {\n"
        "    color: #2c3e50;\n"
        "}\n"
        ".title-label {\n"
        "    color: #2c3e50;\n"
        "    font-size: 24px;\n"
        "    font-weight: bold;\n"
        "}\n"
        ".balance-label {\n"
        "    color: #27ae60;\n"
        "    font-size: 32px;\n"
        "    font-weight: bold;\n"
        "}\n"
        "entry {\n"
        "    background-color: white;\n"
        "    color: #2c3e50;\n"
        "    border: 1px solid #bdc3c7;\n"
        "    border-radius: 4px;\n"
        "    padding: 8px;\n"
        "}\n"
        "entry:focus {\n"
        "    border-color: #3498db;\n"
        "}\n"
        "combobox button {\n"
        "    background-color: white;\n"
        "    border: 1px solid #bdc3c7;\n"
        "}\n"
        ".account-row {\n"
        "    background-color: white;\n"
        "    border-radius: 4px;\n"
        "    margin: 4px;\n"
        "    padding: 8px;\n"
        "}\n"
        ".account-row:hover {\n"
        "    background-color: rgba(52, 152, 219, 0.1);\n"
        "}\n"
        "scrolledwindow {\n"
        "    background-color: transparent;\n"
        "}\n"
        "separator {\n"
        "    background-color: #bdc3c7;\n"
        "}\n";

    /* Remove old provider if exists */
    if (current_css_provider) {
        gtk_style_context_remove_provider_for_screen(
            gdk_screen_get_default(),
            GTK_STYLE_PROVIDER(current_css_provider)
        );
        g_object_unref(current_css_provider);
    }

    gtk_css_provider_load_from_data(provider, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
    );
    current_css_provider = provider;
}

/* Apply theme based on current mode */
static void apply_current_theme(void)
{
    if (app_state.yandere_mode) {
        apply_yandere_css();
    } else {
        apply_normal_css();
    }
}

/* ============================================================================
 * Device Communication (Stub - would use USB HID in real implementation)
 * ============================================================================ */

static int device_connect(void)
{
    /* Stub - would connect via USB HID */
    app_state.device_connected = 1;
    strncpy(app_state.device_id, "RISCV-001-DEMO", sizeof(app_state.device_id));
    strncpy(app_state.firmware_version, "1.0.0", sizeof(app_state.firmware_version));

    /* Add demo accounts */
    app_state.account_count = 3;

    app_state.accounts[0].index = 0;
    app_state.accounts[0].chain = CHAIN_BITCOIN;
    strncpy(app_state.accounts[0].address, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            sizeof(app_state.accounts[0].address));
    strncpy(app_state.accounts[0].label, "Bitcoin Main", sizeof(app_state.accounts[0].label));
    strncpy(app_state.accounts[0].balance, "0.05234 BTC", sizeof(app_state.accounts[0].balance));

    app_state.accounts[1].index = 0;
    app_state.accounts[1].chain = CHAIN_ETHEREUM;
    strncpy(app_state.accounts[1].address, "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
            sizeof(app_state.accounts[1].address));
    strncpy(app_state.accounts[1].label, "Ethereum Main", sizeof(app_state.accounts[1].label));
    strncpy(app_state.accounts[1].balance, "1.25 ETH", sizeof(app_state.accounts[1].balance));

    app_state.accounts[2].index = 0;
    app_state.accounts[2].chain = CHAIN_SOLANA;
    strncpy(app_state.accounts[2].address, "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV",
            sizeof(app_state.accounts[2].address));
    strncpy(app_state.accounts[2].label, "Solana Main", sizeof(app_state.accounts[2].label));
    strncpy(app_state.accounts[2].balance, "15.5 SOL", sizeof(app_state.accounts[2].balance));

    return 0;
}

static void device_disconnect(void)
{
    app_state.device_connected = 0;
    app_state.device_id[0] = '\0';
    app_state.account_count = 0;
}

/* ============================================================================
 * UI Update Functions
 * ============================================================================ */

static void update_connection_status(void);
static void update_account_list(void);

static void update_connection_status(void)
{
    if (app_state.device_connected) {
        gtk_label_set_text(GTK_LABEL(app_state.status_label),
                          get_yandere_connected_msg());
        gtk_button_set_label(GTK_BUTTON(app_state.connect_button), "Stay With Me~");
        gtk_widget_set_sensitive(app_state.stack, TRUE);
    } else {
        gtk_label_set_text(GTK_LABEL(app_state.status_label),
                          get_yandere_disconnected_msg());
        gtk_button_set_label(GTK_BUTTON(app_state.connect_button), "Find My Love~");
        gtk_widget_set_sensitive(app_state.stack, FALSE);
    }
}

static void update_account_list(void)
{
    /* Clear existing list */
    GList *children = gtk_container_get_children(GTK_CONTAINER(app_state.account_list));
    for (GList *iter = children; iter != NULL; iter = g_list_next(iter)) {
        gtk_widget_destroy(GTK_WIDGET(iter->data));
    }
    g_list_free(children);

    /* Add accounts */
    for (size_t i = 0; i < app_state.account_count; i++) {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        gtk_widget_set_margin_start(row, 12);
        gtk_widget_set_margin_end(row, 12);
        gtk_widget_set_margin_top(row, 8);
        gtk_widget_set_margin_bottom(row, 8);

        /* Chain symbol */
        GtkWidget *symbol_label = gtk_label_new(chain_symbols[app_state.accounts[i].chain]);
        PangoAttrList *attr_list = pango_attr_list_new();
        pango_attr_list_insert(attr_list, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
        gtk_label_set_attributes(GTK_LABEL(symbol_label), attr_list);
        pango_attr_list_unref(attr_list);
        gtk_box_pack_start(GTK_BOX(row), symbol_label, FALSE, FALSE, 0);

        /* Account name and address */
        GtkWidget *info_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        gtk_widget_set_hexpand(info_box, TRUE);

        char account_title[128];
        snprintf(account_title, sizeof(account_title), "%s (%s)",
                 app_state.accounts[i].label, chain_names[app_state.accounts[i].chain]);
        GtkWidget *name_label = gtk_label_new(account_title);
        gtk_widget_set_halign(name_label, GTK_ALIGN_START);
        gtk_box_pack_start(GTK_BOX(info_box), name_label, FALSE, FALSE, 0);

        /* Truncate address for display */
        char short_addr[32];
        size_t addr_len = strlen(app_state.accounts[i].address);
        if (addr_len > 20) {
            snprintf(short_addr, sizeof(short_addr), "%.8s...%.8s",
                     app_state.accounts[i].address,
                     app_state.accounts[i].address + addr_len - 8);
        } else {
            strncpy(short_addr, app_state.accounts[i].address, sizeof(short_addr));
        }
        GtkWidget *addr_label = gtk_label_new(short_addr);
        gtk_widget_set_halign(addr_label, GTK_ALIGN_START);
        GtkStyleContext *context = gtk_widget_get_style_context(addr_label);
        gtk_style_context_add_class(context, "dim-label");
        gtk_box_pack_start(GTK_BOX(info_box), addr_label, FALSE, FALSE, 0);

        gtk_box_pack_start(GTK_BOX(row), info_box, TRUE, TRUE, 0);

        /* Balance */
        GtkWidget *balance_label = gtk_label_new(app_state.accounts[i].balance);
        gtk_box_pack_end(GTK_BOX(row), balance_label, FALSE, FALSE, 0);

        gtk_list_box_insert(GTK_LIST_BOX(app_state.account_list), row, -1);
        gtk_widget_show_all(row);
    }
}

/* ============================================================================
 * Signal Handlers
 * ============================================================================ */

static void on_connect_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    if (app_state.device_connected) {
        device_disconnect();
    } else {
        device_connect();
        update_account_list();
    }
    update_connection_status();
}

static void on_send_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    const char *address = gtk_entry_get_text(GTK_ENTRY(app_state.send_address_entry));
    const char *amount = gtk_entry_get_text(GTK_ENTRY(app_state.send_amount_entry));

    if (strlen(address) == 0 || strlen(amount) == 0) {
        GtkWidget *dialog = gtk_message_dialog_new(
            GTK_WINDOW(app_state.main_window),
            GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_ERROR,
            GTK_BUTTONS_OK,
            "You forgot something, senpai~\n"
            "I need both address and amount!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    /* Show confirmation dialog with yandere flair */
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(app_state.main_window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION,
        GTK_BUTTONS_OK_CANCEL,
        "%s\n\n"
        "To: %s\n"
        "Amount: %s\n\n"
        "Confirm on your device, my love~",
        get_yandere_send_msg(), address, amount);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void on_copy_address_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    const char *address = gtk_label_get_text(GTK_LABEL(app_state.receive_address_label));
    GtkClipboard *clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(clipboard, address, -1);

    gtk_label_set_text(GTK_LABEL(app_state.status_label), get_yandere_copy_msg());
}

static void on_verify_address_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(app_state.main_window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_INFO,
        GTK_BUTTONS_OK,
        "Look at your wallet, senpai~\n"
        "Verify this address is truly yours!\n"
        "I want to make sure it's really you...");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void on_receive_account_changed(GtkComboBox *combo, gpointer user_data)
{
    (void)user_data;

    gint selected = gtk_combo_box_get_active(combo);
    if (selected >= 0 && (size_t)selected < app_state.account_count) {
        gtk_label_set_text(GTK_LABEL(app_state.receive_address_label),
                          app_state.accounts[selected].address);
    }
}

static void on_wc_connect_clicked(GtkButton *button, gpointer user_data)
{
    (void)button;
    (void)user_data;

    const char *uri = gtk_entry_get_text(GTK_ENTRY(app_state.wc_uri_entry));

    if (strlen(uri) == 0) {
        GtkWidget *dialog = gtk_message_dialog_new(
            GTK_WINDOW(app_state.main_window),
            GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_ERROR,
            GTK_BUTTONS_OK,
            "Where's the URI, senpai?!\n"
            "I can't connect without it...");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    /* Validate URI format */
    if (strncmp(uri, "wc:", 3) != 0) {
        GtkWidget *dialog = gtk_message_dialog_new(
            GTK_WINDOW(app_state.main_window),
            GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_ERROR,
            GTK_BUTTONS_OK,
            "That's not a valid URI!\n"
            "It should start with 'wc:'\n"
            "Are you trying to trick me?!");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    /* Show session approval dialog with yandere jealousy */
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(app_state.main_window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION,
        GTK_BUTTONS_OK_CANCEL,
        "Another app wants to connect to you?!\n\n"
        "...I'll allow it. But only because you asked~\n"
        "Don't forget, you're MINE!\n\n"
        "Do you really want to connect?");
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void on_sidebar_row_selected(GtkListBox *listbox, GtkListBoxRow *row, gpointer user_data)
{
    (void)listbox;
    (void)user_data;

    if (row == NULL) return;

    int index = gtk_list_box_row_get_index(row);
    const char *pages[] = {"dashboard", "accounts", "send", "receive", "walletconnect", "settings"};

    if (index >= 0 && index < 6) {
        gtk_stack_set_visible_child_name(GTK_STACK(app_state.stack), pages[index]);
    }
}

static void on_theme_changed(GtkComboBox *combo, gpointer user_data)
{
    (void)user_data;

    gint selected = gtk_combo_box_get_active(combo);
    app_state.yandere_mode = (selected == 0) ? 1 : 0;
    apply_current_theme();

    /* Show message based on theme */
    if (app_state.yandere_mode) {
        gtk_label_set_text(GTK_LABEL(app_state.status_label),
                          "Welcome back, senpai~ I missed you!");
    } else {
        gtk_label_set_text(GTK_LABEL(app_state.status_label),
                          "Professional mode enabled");
    }
}

/* ============================================================================
 * Page Builders
 * ============================================================================ */

static GtkWidget *create_dashboard_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);
    gtk_widget_set_margin_start(page, 24);
    gtk_widget_set_margin_end(page, 24);
    gtk_widget_set_margin_top(page, 24);
    gtk_widget_set_margin_bottom(page, 24);

    /* Total balance card */
    GtkWidget *balance_frame = gtk_frame_new(NULL);

    GtkWidget *balance_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(balance_box, 24);
    gtk_widget_set_margin_end(balance_box, 24);
    gtk_widget_set_margin_top(balance_box, 24);
    gtk_widget_set_margin_bottom(balance_box, 24);

    GtkWidget *balance_title = gtk_label_new("Our Treasure Together~");
    gtk_widget_set_halign(balance_title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(balance_box), balance_title, FALSE, FALSE, 0);

    app_state.total_balance_label = gtk_label_new("~$1,234.56 USD");
    PangoAttrList *attr_list = pango_attr_list_new();
    pango_attr_list_insert(attr_list, pango_attr_scale_new(2.0));
    pango_attr_list_insert(attr_list, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
    gtk_label_set_attributes(GTK_LABEL(app_state.total_balance_label), attr_list);
    pango_attr_list_unref(attr_list);
    gtk_widget_set_halign(app_state.total_balance_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(balance_box), app_state.total_balance_label, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(balance_frame), balance_box);
    gtk_box_pack_start(GTK_BOX(page), balance_frame, FALSE, FALSE, 0);

    /* Accounts section */
    GtkWidget *accounts_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(accounts_label), "<b>Your Precious Accounts~</b>");
    gtk_widget_set_halign(accounts_label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(accounts_label, 16);
    gtk_box_pack_start(GTK_BOX(page), accounts_label, FALSE, FALSE, 0);

    /* Account list */
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scrolled, TRUE);

    app_state.account_list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app_state.account_list), GTK_SELECTION_NONE);
    gtk_container_add(GTK_CONTAINER(scrolled), app_state.account_list);

    GtkWidget *list_frame = gtk_frame_new(NULL);
    gtk_container_add(GTK_CONTAINER(list_frame), scrolled);
    gtk_box_pack_start(GTK_BOX(page), list_frame, TRUE, TRUE, 0);

    return page;
}

static GtkWidget *create_accounts_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);
    gtk_widget_set_margin_start(page, 24);
    gtk_widget_set_margin_end(page, 24);
    gtk_widget_set_margin_top(page, 24);
    gtk_widget_set_margin_bottom(page, 24);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<big><b>My Darling's Accounts~</b></big>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), title, FALSE, FALSE, 0);

    GtkWidget *subtitle = gtk_label_new("I'll protect all your addresses forever!");
    gtk_widget_set_halign(subtitle, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), subtitle, FALSE, FALSE, 0);

    /* Add account button */
    GtkWidget *add_button = gtk_button_new_with_label("Add New Love~");
    gtk_widget_set_halign(add_button, GTK_ALIGN_START);
    gtk_widget_set_margin_top(add_button, 16);
    gtk_box_pack_start(GTK_BOX(page), add_button, FALSE, FALSE, 0);

    return page;
}

static GtkWidget *create_send_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(page, 24);
    gtk_widget_set_margin_end(page, 24);
    gtk_widget_set_margin_top(page, 24);
    gtk_widget_set_margin_bottom(page, 24);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<big><b>Send Your Love~</b></big>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), title, FALSE, FALSE, 0);

    GtkWidget *send_subtitle = gtk_label_new("(But why send it to someone else...?)");
    gtk_widget_set_halign(send_subtitle, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), send_subtitle, FALSE, FALSE, 0);

    /* Chain selection */
    GtkWidget *chain_label = gtk_label_new("Choose Your Path~");
    gtk_widget_set_halign(chain_label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(chain_label, 16);
    gtk_box_pack_start(GTK_BOX(page), chain_label, FALSE, FALSE, 0);

    app_state.send_chain_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_state.send_chain_combo), "Bitcoin");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_state.send_chain_combo), "Ethereum");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_state.send_chain_combo), "Litecoin");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_state.send_chain_combo), "Solana");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app_state.send_chain_combo), 0);
    gtk_box_pack_start(GTK_BOX(page), app_state.send_chain_combo, FALSE, FALSE, 0);

    /* Recipient address */
    GtkWidget *addr_label = gtk_label_new("Who Gets Your Attention?");
    gtk_widget_set_halign(addr_label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(addr_label, 16);
    gtk_box_pack_start(GTK_BOX(page), addr_label, FALSE, FALSE, 0);

    app_state.send_address_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app_state.send_address_entry),
                                   "Their address... I'll remember it~");
    gtk_box_pack_start(GTK_BOX(page), app_state.send_address_entry, FALSE, FALSE, 0);

    /* Amount */
    GtkWidget *amount_label = gtk_label_new("How Much Love to Give?");
    gtk_widget_set_halign(amount_label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(amount_label, 16);
    gtk_box_pack_start(GTK_BOX(page), amount_label, FALSE, FALSE, 0);

    GtkWidget *amount_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    app_state.send_amount_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app_state.send_amount_entry), "0.00");
    gtk_widget_set_hexpand(app_state.send_amount_entry, TRUE);
    gtk_box_pack_start(GTK_BOX(amount_box), app_state.send_amount_entry, TRUE, TRUE, 0);

    GtkWidget *max_button = gtk_button_new_with_label("ALL OF IT!");
    gtk_box_pack_start(GTK_BOX(amount_box), max_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page), amount_box, FALSE, FALSE, 0);

    /* Fee */
    app_state.send_fee_label = gtk_label_new("Network tribute: ~0.0001 BTC");
    gtk_widget_set_halign(app_state.send_fee_label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(app_state.send_fee_label, 8);
    gtk_box_pack_start(GTK_BOX(page), app_state.send_fee_label, FALSE, FALSE, 0);

    /* Send button */
    app_state.send_button = gtk_button_new_with_label("Send With My Blessing~");
    gtk_widget_set_margin_top(app_state.send_button, 24);
    g_signal_connect(app_state.send_button, "clicked", G_CALLBACK(on_send_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(page), app_state.send_button, FALSE, FALSE, 0);

    return page;
}

static GtkWidget *create_receive_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(page, 24);
    gtk_widget_set_margin_end(page, 24);
    gtk_widget_set_margin_top(page, 24);
    gtk_widget_set_margin_bottom(page, 24);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<big><b>Receive Gifts~</b></big>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), title, FALSE, FALSE, 0);

    GtkWidget *recv_subtitle = gtk_label_new("Share this address and they'll send you love!");
    gtk_widget_set_halign(recv_subtitle, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), recv_subtitle, FALSE, FALSE, 0);

    /* Account selection */
    GtkWidget *account_label = gtk_label_new("Which Heart to Fill?");
    gtk_widget_set_halign(account_label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(account_label, 16);
    gtk_box_pack_start(GTK_BOX(page), account_label, FALSE, FALSE, 0);

    app_state.receive_account_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_state.receive_account_combo), "Bitcoin Main");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_state.receive_account_combo), "Ethereum Main");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_state.receive_account_combo), "Solana Main");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app_state.receive_account_combo), 0);
    g_signal_connect(app_state.receive_account_combo, "changed",
                     G_CALLBACK(on_receive_account_changed), NULL);
    gtk_box_pack_start(GTK_BOX(page), app_state.receive_account_combo, FALSE, FALSE, 0);

    /* QR Code placeholder */
    GtkWidget *qr_frame = gtk_frame_new(NULL);
    gtk_widget_set_size_request(qr_frame, 200, 200);
    gtk_widget_set_halign(qr_frame, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(qr_frame, 24);

    GtkWidget *qr_placeholder = gtk_label_new("[QR Code]\nScan me, senpai~");
    gtk_container_add(GTK_CONTAINER(qr_frame), qr_placeholder);
    gtk_box_pack_start(GTK_BOX(page), qr_frame, FALSE, FALSE, 0);

    /* Address display */
    app_state.receive_address_label = gtk_label_new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
    gtk_label_set_selectable(GTK_LABEL(app_state.receive_address_label), TRUE);
    gtk_label_set_line_wrap(GTK_LABEL(app_state.receive_address_label), TRUE);
    gtk_widget_set_margin_top(app_state.receive_address_label, 16);
    gtk_box_pack_start(GTK_BOX(page), app_state.receive_address_label, FALSE, FALSE, 0);

    /* Action buttons */
    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_halign(button_box, GTK_ALIGN_CENTER);
    gtk_widget_set_margin_top(button_box, 16);

    app_state.copy_address_button = gtk_button_new_with_label("Keep In Heart~");
    g_signal_connect(app_state.copy_address_button, "clicked",
                     G_CALLBACK(on_copy_address_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(button_box), app_state.copy_address_button, FALSE, FALSE, 0);

    app_state.verify_button = gtk_button_new_with_label("Prove It's Real!");
    g_signal_connect(app_state.verify_button, "clicked",
                     G_CALLBACK(on_verify_address_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(button_box), app_state.verify_button, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(page), button_box, FALSE, FALSE, 0);

    return page;
}

static GtkWidget *create_walletconnect_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(page, 24);
    gtk_widget_set_margin_end(page, 24);
    gtk_widget_set_margin_top(page, 24);
    gtk_widget_set_margin_bottom(page, 24);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<big><b>Other Connections...</b></big>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), title, FALSE, FALSE, 0);

    GtkWidget *subtitle = gtk_label_new("I guess you can connect to OTHER apps... if you must.");
    gtk_widget_set_halign(subtitle, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), subtitle, FALSE, FALSE, 0);

    /* New connection section */
    GtkWidget *connect_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(connect_label), "<b>New Rival Connection</b>");
    gtk_widget_set_halign(connect_label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(connect_label, 24);
    gtk_box_pack_start(GTK_BOX(page), connect_label, FALSE, FALSE, 0);

    GtkWidget *uri_label = gtk_label_new("Paste their URI... I'll be watching.");
    gtk_widget_set_halign(uri_label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(uri_label, 8);
    gtk_box_pack_start(GTK_BOX(page), uri_label, FALSE, FALSE, 0);

    app_state.wc_uri_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(app_state.wc_uri_entry), "wc:... (I'm not jealous!)");
    gtk_box_pack_start(GTK_BOX(page), app_state.wc_uri_entry, FALSE, FALSE, 0);

    app_state.wc_connect_button = gtk_button_new_with_label("Allow Them... For Now~");
    gtk_widget_set_halign(app_state.wc_connect_button, GTK_ALIGN_START);
    gtk_widget_set_margin_top(app_state.wc_connect_button, 8);
    g_signal_connect(app_state.wc_connect_button, "clicked",
                     G_CALLBACK(on_wc_connect_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(page), app_state.wc_connect_button, FALSE, FALSE, 0);

    /* Active sessions */
    GtkWidget *sessions_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(sessions_label), "<b>My Rivals (Active Sessions)</b>");
    gtk_widget_set_halign(sessions_label, GTK_ALIGN_START);
    gtk_widget_set_margin_top(sessions_label, 24);
    gtk_box_pack_start(GTK_BOX(page), sessions_label, FALSE, FALSE, 0);

    GtkWidget *no_sessions = gtk_label_new("Good... no one else is connected. Just us~");
    gtk_widget_set_halign(no_sessions, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), no_sessions, FALSE, FALSE, 0);

    return page;
}

static GtkWidget *create_settings_page(void)
{
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(page, 24);
    gtk_widget_set_margin_end(page, 24);
    gtk_widget_set_margin_top(page, 24);
    gtk_widget_set_margin_bottom(page, 24);

    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<big><b>Our Secret Settings~</b></big>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(page), title, FALSE, FALSE, 0);

    /* Device info */
    GtkWidget *device_frame = gtk_frame_new("My Beloved Device");
    gtk_widget_set_margin_top(device_frame, 16);

    GtkWidget *device_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(device_box, 12);
    gtk_widget_set_margin_end(device_box, 12);
    gtk_widget_set_margin_top(device_box, 12);
    gtk_widget_set_margin_bottom(device_box, 12);

    GtkWidget *model_label = gtk_label_new("Model: RISC-V Cold Wallet (My One True Love)");
    gtk_widget_set_halign(model_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(device_box), model_label, FALSE, FALSE, 0);

    GtkWidget *fw_label = gtk_label_new("Firmware: 1.0.0 (Perfect, just like you~)");
    gtk_widget_set_halign(fw_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(device_box), fw_label, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(device_frame), device_box);
    gtk_box_pack_start(GTK_BOX(page), device_frame, FALSE, FALSE, 0);

    /* App info */
    GtkWidget *app_frame = gtk_frame_new("About Your Yandere~");
    gtk_widget_set_margin_top(app_frame, 16);

    GtkWidget *app_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(app_box, 12);
    gtk_widget_set_margin_end(app_box, 12);
    gtk_widget_set_margin_top(app_box, 12);
    gtk_widget_set_margin_bottom(app_box, 12);

    char version_str[64];
    snprintf(version_str, sizeof(version_str), "%s v%s", APP_NAME, APP_VERSION);
    GtkWidget *version_label = gtk_label_new(version_str);
    gtk_widget_set_halign(version_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(app_box), version_label, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(app_frame), app_box);
    gtk_box_pack_start(GTK_BOX(page), app_frame, FALSE, FALSE, 0);

    /* Theme selection */
    GtkWidget *theme_frame = gtk_frame_new("Appearance (My Look~)");
    gtk_widget_set_margin_top(theme_frame, 16);

    GtkWidget *theme_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(theme_box, 12);
    gtk_widget_set_margin_end(theme_box, 12);
    gtk_widget_set_margin_top(theme_box, 12);
    gtk_widget_set_margin_bottom(theme_box, 12);

    GtkWidget *theme_label = gtk_label_new("Theme:");
    gtk_widget_set_halign(theme_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(theme_box), theme_label, FALSE, FALSE, 0);

    app_state.theme_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_state.theme_combo),
                                   "Yandere Mode~ (Default)");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(app_state.theme_combo),
                                   "Normal Mode (Boring...)");
    gtk_combo_box_set_active(GTK_COMBO_BOX(app_state.theme_combo),
                             app_state.yandere_mode ? 0 : 1);
    g_signal_connect(app_state.theme_combo, "changed",
                     G_CALLBACK(on_theme_changed), NULL);
    gtk_box_pack_start(GTK_BOX(theme_box), app_state.theme_combo, FALSE, FALSE, 0);

    GtkWidget *theme_desc = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(theme_desc),
                        "<small><i>Yandere mode: Pink theme with loving messages~\n"
                        "Normal mode: Professional look (but why? I'll be sad...)</i></small>");
    gtk_widget_set_halign(theme_desc, GTK_ALIGN_START);
    gtk_widget_set_margin_top(theme_desc, 8);
    gtk_box_pack_start(GTK_BOX(theme_box), theme_desc, FALSE, FALSE, 0);

    gtk_container_add(GTK_CONTAINER(theme_frame), theme_box);
    gtk_box_pack_start(GTK_BOX(page), theme_frame, FALSE, FALSE, 0);

    return page;
}

static GtkWidget *create_sidebar(void)
{
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scrolled, 200, -1);

    app_state.sidebar_list = gtk_list_box_new();
    GtkStyleContext *sidebar_ctx = gtk_widget_get_style_context(app_state.sidebar_list);
    gtk_style_context_add_class(sidebar_ctx, "sidebar");

    const char *items[] = {
        "My Dashboard~",
        "Our Accounts",
        "Send Love~",
        "Receive Gifts",
        "Rivals...",
        "Secrets~"
    };

    for (size_t i = 0; i < 6; i++) {
        GtkWidget *row = gtk_label_new(items[i]);
        gtk_widget_set_halign(row, GTK_ALIGN_START);
        gtk_widget_set_margin_start(row, 12);
        gtk_widget_set_margin_end(row, 12);
        gtk_widget_set_margin_top(row, 12);
        gtk_widget_set_margin_bottom(row, 12);
        gtk_list_box_insert(GTK_LIST_BOX(app_state.sidebar_list), row, -1);
    }

    g_signal_connect(app_state.sidebar_list, "row-selected",
                     G_CALLBACK(on_sidebar_row_selected), NULL);

    gtk_container_add(GTK_CONTAINER(scrolled), app_state.sidebar_list);

    return scrolled;
}

/* ============================================================================
 * Application Lifecycle
 * ============================================================================ */

static void activate(GtkApplication *app, gpointer user_data)
{
    (void)user_data;

    /* Apply current theme (yandere by default) */
    apply_current_theme();

    /* Create main window */
    app_state.main_window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(app_state.main_window), APP_NAME);
    gtk_window_set_default_size(GTK_WINDOW(app_state.main_window), 1000, 700);

    /* Main vertical box */
    GtkWidget *main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* Header bar area */
    GtkWidget *header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_start(header_box, 12);
    gtk_widget_set_margin_end(header_box, 12);
    gtk_widget_set_margin_top(header_box, 8);
    gtk_widget_set_margin_bottom(header_box, 8);

    /* Yuno/Ayano heart icon */
    GtkWidget *heart_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(heart_label), "<span color='#DC143C' size='x-large'>♥</span>");
    gtk_box_pack_start(GTK_BOX(header_box), heart_label, FALSE, FALSE, 0);

    GtkWidget *app_title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(app_title), "<span color='white'><b>Yandere Wallet~</b></span>");
    GtkStyleContext *title_ctx = gtk_widget_get_style_context(app_title);
    gtk_style_context_add_class(title_ctx, "app-title");
    gtk_box_pack_start(GTK_BOX(header_box), app_title, FALSE, FALSE, 0);

    GtkWidget *subtitle = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(subtitle), "<span color='#FFB6C1' size='small'><i>I'll protect your keys forever~</i></span>");
    gtk_box_pack_start(GTK_BOX(header_box), subtitle, FALSE, FALSE, 8);

    /* Spacer */
    GtkWidget *spacer = gtk_label_new("");
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_pack_start(GTK_BOX(header_box), spacer, TRUE, TRUE, 0);

    /* Connection status */
    app_state.status_label = gtk_label_new(get_yandere_disconnected_msg());
    GtkStyleContext *status_ctx = gtk_widget_get_style_context(app_state.status_label);
    gtk_style_context_add_class(status_ctx, "status-label");
    gtk_box_pack_start(GTK_BOX(header_box), app_state.status_label, FALSE, FALSE, 0);

    app_state.connect_button = gtk_button_new_with_label("Find My Love~");
    g_signal_connect(app_state.connect_button, "clicked", G_CALLBACK(on_connect_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(header_box), app_state.connect_button, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(main_vbox), header_box, FALSE, FALSE, 0);

    /* Separator */
    GtkWidget *hsep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(main_vbox), hsep, FALSE, FALSE, 0);

    /* Main content box */
    GtkWidget *content_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_vexpand(content_box, TRUE);

    /* Sidebar */
    app_state.sidebar = create_sidebar();
    gtk_box_pack_start(GTK_BOX(content_box), app_state.sidebar, FALSE, FALSE, 0);

    /* Vertical separator */
    GtkWidget *vsep = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
    gtk_box_pack_start(GTK_BOX(content_box), vsep, FALSE, FALSE, 0);

    /* Content stack */
    app_state.stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(app_state.stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_widget_set_hexpand(app_state.stack, TRUE);
    gtk_widget_set_vexpand(app_state.stack, TRUE);

    /* Add pages */
    gtk_stack_add_named(GTK_STACK(app_state.stack), create_dashboard_page(), "dashboard");
    gtk_stack_add_named(GTK_STACK(app_state.stack), create_accounts_page(), "accounts");
    gtk_stack_add_named(GTK_STACK(app_state.stack), create_send_page(), "send");
    gtk_stack_add_named(GTK_STACK(app_state.stack), create_receive_page(), "receive");
    gtk_stack_add_named(GTK_STACK(app_state.stack), create_walletconnect_page(), "walletconnect");
    gtk_stack_add_named(GTK_STACK(app_state.stack), create_settings_page(), "settings");

    gtk_box_pack_start(GTK_BOX(content_box), app_state.stack, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(main_vbox), content_box, TRUE, TRUE, 0);

    gtk_container_add(GTK_CONTAINER(app_state.main_window), main_vbox);

    /* Initial state */
    update_connection_status();

    /* Select first sidebar item */
    GtkListBoxRow *first_row = gtk_list_box_get_row_at_index(GTK_LIST_BOX(app_state.sidebar_list), 0);
    gtk_list_box_select_row(GTK_LIST_BOX(app_state.sidebar_list), first_row);

    gtk_widget_show_all(app_state.main_window);
}

int main(int argc, char *argv[])
{
    /* Seed random for yandere messages */
    srand((unsigned int)time(NULL));

    memset(&app_state, 0, sizeof(app_state));
    pthread_mutex_init(&app_state.mutex, NULL);
    app_state.running = 1;
    app_state.yandere_mode = 1;  /* Yandere theme is default! */

    GtkApplication *app = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);

    int status = g_application_run(G_APPLICATION(app), argc, argv);

    app_state.running = 0;
    pthread_mutex_destroy(&app_state.mutex);
    g_object_unref(app);

    return status;
}
