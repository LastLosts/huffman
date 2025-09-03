#include <cassert>
#include <climits>
#include <cmath>
#include <fstream>
#include <iostream>
#include <queue>
#include <thread>
#include <vector>

struct Node
{
    Node() : ch{'\0'}, freq{0}, left{nullptr}, right{nullptr} {}
    Node(char character, uint32_t frequency, Node *_left = nullptr, Node *_right = nullptr)
        : ch{character}, freq{frequency}, left{_left}, right{_right}
    {
    }

    char ch;
    uint32_t freq;
    Node *left;
    Node *right;
};
struct comp
{
    bool operator()(Node *l, Node *r) { return l->freq > r->freq; }
};
struct NodeEncoded
{
    uint64_t hex{0};
    uint8_t length{0};
};

// Utility and debug functions
static uint32_t get_tree_depth(Node *root, uint32_t counter = 1)
{
    if (root->left && root->right)
    {
        return std::max(get_tree_depth(root->left, counter + 1), get_tree_depth(root->right, counter + 1));
    }
    if (root->left)
    {
        return counter + 1;
    }
    if (root->right)
    {
        return counter + 1;
    }
    return counter;
}

static void print_tree_impl(const std::string &prefix, const Node *node, bool isLeft)
{
    if (node != nullptr)
    {
        std::cout << prefix;

        std::cout << (isLeft ? "├──" : "└──");

        // print the value of the node
        if (node->ch != '\0')
            std::cout << node->ch << std::endl;
        else
            std::cout << "[]" << std::endl;

        // enter the next tree level - left and right branch
        if (node->left)
            print_tree_impl(prefix + (isLeft ? "│   " : "    "), node->left, true);
        if (node->right)
            print_tree_impl(prefix + (isLeft ? "│   " : "    "), node->right, false);
    }
}

static void print_tree(Node *root)
{
    print_tree_impl("", root, true);
}
static void print_table(uint32_t *table, bool only_non_zero = true)
{
    for (int i = 0; i < 256; ++i)
    {
        if (only_non_zero && table[i] != 0)
            std::cout << (char)(i - 128) << ": " << table[i] << "\n";
    }
}
static uint64_t get_bit(uint64_t hex, uint8_t bit_number)
{
    assert(bit_number <= 64);
    return (hex << (64 - bit_number)) >> 63;
}

static void print_binary(NodeEncoded node)
{
    for (int i = node.length; i > 0; --i)
    {
        std::cout << get_bit(node.hex, i);
    }
}
static void generate_codes_str(Node *root, const std::string &encoded, std::string *huffman_codes)
{
    if (!root)
        return;

    // If leaf
    if (!root->left && !root->right)
        huffman_codes[root->ch + 128] = encoded;

    generate_codes_str(root->left, encoded + "0", huffman_codes);
    generate_codes_str(root->right, encoded + "1", huffman_codes);
}
static void print_byte_binary(char byte)
{
    for (uint8_t i = 8; i > 0; --i)
    {
        std::cout << get_bit(byte, i);
    }
}
static void print_file_binary(const char *filename)
{
    std::fstream in_file{filename, std::ios_base::in | std::ios_base::binary};

    if (!in_file.is_open())
    {
        std::cerr << "Failed to open file for read " << filename << "\n";
        return;
    }

    while (true)
    {
        char byte;
        in_file.read(&byte, 1);
        if (in_file.gcount() == 0)
            break;

        std::cout << byte << " : ";
        print_byte_binary(byte);
        std::cout << "\n";
    }
    in_file.close();
}
static void print_readable_char(char c)
{
    switch (c)
    {
    case '\n': {
        std::cout << "'\\n'";
        break;
    }
    case '\0': {
        std::cout << "'\\0'";
        break;
    }
    case ' ': {
        std::cout << "' '";
        break;
    }
    default: {
        std::cout << c;
        break;
    }
    }
}

static void print_huffman_codes(NodeEncoded *huffman_codes)
{
    for (int i = 0; i < 256; ++i)
    {
        if (huffman_codes[i].length == 0)
            continue;
        print_readable_char(i - 128);
        std::cout << " ";
        print_binary(huffman_codes[i]);
        std::cout << "\n";
    }
}

// Actual work functions
static void append_frequency_table(uint32_t *table, char *data, uint32_t data_size)
{
    for (int i = 0; i < data_size; ++i)
    {
        table[data[i] + 128]++;
    }
}

static uint32_t *build_frequency_table(std::fstream &file)
{
    uint32_t read_size = 100 * 1000 * 1000;
    std::vector<char> data(read_size);

    // uint32_t *table = (uint32_t *)malloc(256 * sizeof(uint32_t));
    uint32_t *table = (uint32_t *)calloc(256, sizeof(uint32_t));

    while (true)
    {
        file.read(data.data(), read_size);
        uint32_t bytes_red = file.gcount();

        if (bytes_red == 0)
            break;

        append_frequency_table(table, data.data(), bytes_red);
    }
    return table;
}

static void build_frequency_table_multithread(const std::ifstream &file)
{
    std::cout << "No impl" << std::endl;
    exit(-1);
}

static Node *build_huffman_tree(uint32_t *table, Node *tree_arena)
{
    std::priority_queue<Node *, std::vector<Node *>, comp> queue;
    uint32_t arena_index = 0;

    for (int i = 0; i < 256; ++i)
    {
        if (table[i] != 0)
        {
            Node *new_node = tree_arena + arena_index;
            new_node->ch = i - 128;
            new_node->freq = table[i];
            // std::cout << "Pushing node " << new_node->ch << " " << new_node->freq << "\n";
            queue.push(new_node);
            arena_index++;
        }
    }

    while (queue.size() > 1)
    {
        Node *left = queue.top();
        queue.pop();
        Node *right = queue.top();
        queue.pop();

        // std::cout << "Combining " << left->ch << " " << right->ch << "\n";

        Node *combined = tree_arena + arena_index;
        arena_index++;
        combined->ch = '\0';
        combined->freq = left->freq + right->freq;
        combined->left = left;
        combined->right = right;
        queue.push(combined);
    }

    return queue.top();
}

static void generate_codes(Node *root, NodeEncoded encoded, NodeEncoded *huffman_codes)
{
    // If leaf
    if (!root->left && !root->right)
    {
        huffman_codes[root->ch + 128] = encoded;
        assert(root->ch != '\0');
        return;
    }

    generate_codes(root->left, {encoded.hex << 1, (uint8_t)(encoded.length + 1)}, huffman_codes);
    generate_codes(root->right, {(encoded.hex << 1) + 1, (uint8_t)(encoded.length + 1)}, huffman_codes);
}

static void encode_chunk(const char *data, uint32_t data_size, std::vector<char> &out_data, NodeEncoded *huffman_codes)
{
    out_data.clear();

    unsigned char byte = 0;
    int bits_left = 8;

    for (uint32_t i = 0; i < data_size; ++i)
    {
        NodeEncoded current_code = huffman_codes[data[i] + 128];

        assert(current_code.length > 0);
        while (bits_left >= current_code.length)
        {
            byte = (byte << current_code.length) | current_code.hex;
            bits_left -= current_code.length;

            ++i;
            if (i >= data_size)
            {
                byte = byte << bits_left;

                out_data.push_back(byte - 128);
                return;
            }
            current_code = huffman_codes[data[i] + 128];
        }
        if (bits_left > 0)
        {

            uint32_t bits_left_in_data = current_code.length - bits_left;
            // Shoving in bits that left in current byte
            byte = (byte << bits_left) | (current_code.hex >> (bits_left_in_data));

            out_data.push_back(byte - 128);
            byte = 0;
            // Other bits will be showed into a next byte
            byte = byte | ((current_code.hex << (64 - bits_left_in_data)) >> (64 - bits_left_in_data));
            bits_left = 8 - bits_left_in_data;
        }
        else
        {
            // Byte was perfercly packed
            out_data.push_back(byte - 128);
            byte = 0;
            bits_left = 8;
            --i;
        }
    }
}
static void encode_chunk_big(const char *data, uint32_t data_size, std::vector<uint64_t> &out_data,
                             NodeEncoded *huffman_codes)
{
    out_data.clear();

    uint64_t encode_unit = 0;
    int bits_left = 64;

    for (uint32_t i = 0; i < data_size; ++i)
    {
        NodeEncoded current_code = huffman_codes[data[i] + 128];

        assert(current_code.length > 0);

        while (bits_left >= current_code.length)
        {
            encode_unit = (encode_unit << current_code.length) | current_code.hex;
            bits_left -= current_code.length;
            ++i;

            if (i >= data_size)
            {
                encode_unit = encode_unit << bits_left;

                out_data.push_back(encode_unit);
                return;
            }
            current_code = huffman_codes[data[i] + 128];
        }
        if (bits_left > 0)
        {
            uint32_t bits_left_in_data = current_code.length - bits_left;
            // Shoving in bits that left in current byte
            encode_unit = (encode_unit << bits_left) | (current_code.hex >> (bits_left_in_data));

            out_data.push_back(encode_unit);
            encode_unit = 0;
            // Other bits will be showed into a next byte
            encode_unit = encode_unit | ((current_code.hex << (64 - bits_left_in_data)) >> (64 - bits_left_in_data));
            bits_left = 64 - bits_left_in_data;
        }
        else
        {
            // Byte was perfercly packed
            out_data.push_back(encode_unit);
            encode_unit = 0;
            bits_left = 64;
            --i;
        }
    }
}

static void encode(const char *output_filename, NodeEncoded *huffman_codes, const char *input_filename)
{
    const uint32_t chunk_size = 10 * 1000 * 1000; // 10M
    std::fstream out_file{output_filename, std::ios_base::out | std::ios_base::binary};
    std::fstream in_file{input_filename, std::ios_base::in | std::ios_base::binary};

    if (!out_file.is_open())
    {
        std::cerr << "Failed to open file for write " << output_filename << "\n";
        return;
    }
    if (!in_file.is_open())
    {
        std::cerr << "Failed to open file for read " << input_filename << "\n";
        return;
    }

    std::vector<char> chunk_data(chunk_size);

    while (true)
    {
        in_file.read(chunk_data.data(), chunk_size);
        uint32_t bytes_red = in_file.gcount();
        if (bytes_red == 0)
            break;
        std::cout << "read " << bytes_red << "B\n";

        // One byte at a time encoding if you care about every byte ,which is kind of stupid
        // std::vector<char> encoded;
        // encode_chunk(chunk_data.data(), bytes_red, encoded, huffman_codes);
        // for (auto &&e : encoded)
        // {
        //     std::cout << e << ": ";
        //     print_binary({uint32_t(e + 128), 8});
        //     std::cout << "\n";
        // }
        // if (encoded.size() != 0)
        // {
        //     std::cout << "Wrote " << encoded.size() << "B\n";
        // }
        // out_file.write((char *)encoded.data(), encoded.size());

        std::vector<uint64_t> encoded;
        encode_chunk_big(chunk_data.data(), bytes_red, encoded, huffman_codes);
        // std::cout << "binary: ";
        // print_binary({encoded[0], 64});
        // std::cout << "\n";

        if (encoded.size() != 0)
        {
            std::cout << "Wrote " << encoded.size() * 8 << "B\n";
        }

        out_file.write((char *)encoded.data(), encoded.size() * 8);
    }
    in_file.close();
    out_file.close();
}

int main(int argc, char **argv)
{
    uint32_t max_threads = std::thread::hardware_concurrency();

    if (argc < 1)
    {
        std::cout << "provide file please\n";
        return -1;
    }

    std::fstream file{argv[1], std::ios_base::binary | std::ios_base::in};
    if (!file.is_open())
    {
        std::cout << "file not present\n";
        return -1;
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    uint32_t *table = build_frequency_table(file);
    file.close();

    uint32_t non_zero_chars{};
    for (int i = 0; i < 256; ++i)
    {
        if (table[i] != 0)
        {
            non_zero_chars++;
        }
    }
    // std::cout << "non_zero_chars: " << non_zero_chars << "\n";

    Node *tree_arena = (Node *)calloc(non_zero_chars * 2 - 1, sizeof(Node));
    Node *root = build_huffman_tree(table, tree_arena);

    // std::cout << "Tree depth: " << get_tree_depth(root) << "\n";
    // print_tree(root);

    // Debug?
    // std::string huffman_codes_str[256];
    // generate_codes_str(root, "", huffman_codes_str);

    // for (int i = 0; i < 256; ++i)
    // {
    //     if (huffman_codes_str[i].empty())
    //         continue;
    //     std::cout << char(i - 128) << " " << huffman_codes_str[i] << "\n";
    // }

    NodeEncoded huffman_codes[256];
    generate_codes(root, {0x0, 0}, huffman_codes);

    print_huffman_codes(huffman_codes);

    uint8_t max_huffman_length = 0;
    uint64_t total_bit_length = 0;

    for (int i = 0; i < 256; ++i)
    {
        max_huffman_length = std::max(max_huffman_length, huffman_codes[i].length);
        total_bit_length += table[i] * huffman_codes[i].length;
    }
    // if (max_huffman_length > 8)
    // {
    //     std::cout << "More then 8 bit huffman codes are not supported yet\n";
    //     return -1;
    // }

    assert(get_tree_depth(root) - 1 == max_huffman_length);

    encode("./output.huff", huffman_codes, argv[1]);

    uint64_t total_byte_length_encoded = std::ceil((float)total_bit_length / 8.0f);
    // std::cout << "Bits encoded " << total_bit_length << "\n";
    // std::cout << "Compressed from " << file_size << "B to " << total_byte_length_encoded << "B (perfect size)\n";

    // Not needed OS does its thing
    // free(table);
    // free(tree_arena);
}
