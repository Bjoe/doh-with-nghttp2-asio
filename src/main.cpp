#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <vector>
#include <string>
#include <bitset>
#include <algorithm>
#include <boost/tokenizer.hpp>
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include <boost/preprocessor/punctuation/comma.hpp>
#include <boost/preprocessor/control/iif.hpp>
#include <boost/preprocessor/comparison/equal.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/size.hpp>
#include <boost/preprocessor/seq/seq.hpp>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>

#include <nghttp2/asio_http2_client.h>

#define ENUM_CLASS(name, values)                               \
enum name {                              \
  BOOST_PP_SEQ_FOR_EACH(DEFINE_ENUM_VALUE, , values)          \
};                                                            \
  inline const char* format_##name(name val) {                  \
    switch (val) {                                              \
      BOOST_PP_SEQ_FOR_EACH(DEFINE_ENUM_FORMAT, , values)       \
      default:                                                    \
      return 0;                                               \
  }                                                           \
}

#define DEFINE_ENUM_VALUE(r, data, elem)                        \
BOOST_PP_SEQ_HEAD(elem)                                       \
  BOOST_PP_IIF(BOOST_PP_EQUAL(BOOST_PP_SEQ_SIZE(elem), 2),      \
                                                                = BOOST_PP_SEQ_TAIL(elem), )                     \
  BOOST_PP_COMMA()

#define DEFINE_ENUM_FORMAT(r, data, elem)             \
  case BOOST_PP_SEQ_HEAD(elem):                       \
  return BOOST_PP_STRINGIZE(BOOST_PP_SEQ_HEAD(elem));

namespace ssl = boost::asio::ssl;
namespace http = boost::beast::http;
namespace net = boost::asio;
using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::client;
using tcp = boost::asio::ip::tcp;

constexpr const static int VERSION = 11;
constexpr const static int RCODE_FIELD = 0;
constexpr const static int TC_FIELD = 6;
constexpr const static int RD_FIELD = 7;
constexpr const static int RA_FIELD = 8;
constexpr const static int OPCODE_FIELD = 11;
constexpr const static unsigned short PORT = 443;
constexpr const static unsigned short PROXY_PORT = 8080;
constexpr const static char* DOH_URI = "/dns-query";


ENUM_CLASS(Type,
  ((GET))
  ((POST))
  )

namespace {
std::string Base64UrlEncode(const std::string& input) {
  using namespace boost::archive::iterators;
  using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
  auto base64 = std::string(It(std::begin(input)), It(std::end(input)));

        // Replace characters according to Base64url standard
  boost::replace_all(base64, "+", "-");
  boost::replace_all(base64, "/", "_");
  boost::replace_all(base64, "=", "");

  return base64;
}

std::string Base64UrlDecode(const std::string& input) {
  using namespace boost::archive::iterators;
  using namespace boost::archive::iterators;
  using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

  std::string base64url = input;
  // Replace characters back to standard Base64
  boost::replace_all(base64url, "-", "+");
  boost::replace_all(base64url, "_", "/");
  // Add padding if necessary
  while (base64url.length() % 4 != 0)
    base64url += "=";


  return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(base64url)), It(std::end(base64url))), [](char c) {
    return c == '\0';
  });
}

// Function to combine two uint8_ts into a uint16_t
std::uint16_t combineBytes(std::uint8_t highByte, std::uint8_t lowByte) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(highByte)) << 8) | (lowByte & 0xff);
}

std::uint32_t combineTwoUint16s(std::uint16_t highByte, std::uint16_t lowByte){
  return static_cast<std::uint32_t>((static_cast<std::uint32_t>(highByte)) << 16) | (lowByte & 0xffff);
}

std::tuple<std::vector<std::uint8_t>, std::size_t> parseDomain(const std::vector<std::uint8_t> &data) {
  std::vector<std::uint8_t> dName{};
  std::size_t s = data.at(0);
  dName.push_back(static_cast<std::uint8_t>(s));
  std::size_t offset = 1;
  do {
    for(std::size_t x{}; x < s; x++) {
      dName.push_back(data.at(offset + x));
    }
    offset = offset + s;
    s = data.at(offset);
    offset++;
    dName.push_back(static_cast<std::uint8_t>(s));
  } while(s != 0);
  return std::make_tuple(dName, offset);
}

}

std::istream& operator>>(std::istream& in, Type& options)
{
  std::string token;
  in >> token;
  if (token == format_Type(GET))
    options = Type::GET;
  else if (token == format_Type(POST))
    options = Type::POST;
  else
    in.setstate(std::ios_base::failbit);
  return in;
}

// OPCODE          A four bit field that specifies kind of query in this
//                 message.  This value is set by the originator of a query
//                 and copied into the response.  The values are:
ENUM_CLASS(OPCode,
  ((QUERY)(0))      // 0               a standard query (QUERY)
  ((IQUERY))        // 1               an inverse query (IQUERY)
  ((STATUS))        // 2               a server status request (STATUS)
  // 3-15            reserved for future use
  )

// TC              TrunCation - specifies that this message was truncated
//                 due to length greater than that permitted on the
//                 transmission channel.
ENUM_CLASS(Tc,
  ((NO_TRUNCATION)(0))
  ((TRUNCATION))
  )

// RD              Recursion Desired - this bit may be set in a query and
//                 is copied into the response.  If RD is set, it directs
//                 the name server to pursue the query recursively.
//                 Recursive query support is optional.
ENUM_CLASS(Rd,
  ((NO_RECURSION_DESIRED)(0))
  ((RECURSION_DESIRED))
  )

// RA              Recursion Available - this be is set or cleared in a
//                 response, and denotes whether recursive query support is
//                 available in the name server.
ENUM_CLASS(Ra,
  ((NO_RECURSION_AVAILABLE)(0))
  ((RECURSION_AVAILABLE))
  )

// RCODE           Response code - this 4 bit field is set as part of
//                 responses.  The values have the following
//                 interpretation:
ENUM_CLASS(RCode,
  ((NO_ERROR)(0))         //    0               No error condition
  ((FORMAT_ERROR))        //    1               Format error - The name server was
                  //                    unable to interpret the query.
  ((SERVER_FAILURE))      //    2               Server failure - The name server was
                    //                    unable to process this query due to a
                    //                    problem with the name server.
  ((NAME_ERROR))          //    3               Name Error - Meaningful only for
                //                    responses from an authoritative name
                //                    server, this code signifies that the
                //                    domain name referenced in the query does
                //                    not exist.
  ((NOT_IMPLEMENTED))     //    4               Not Implemented - The name server does
                     //                    not support the requested kind of query.
  ((REFUSED))             //    5               Refused - The name server refuses to
             //                    perform the specified operation for
             //                    policy reasons.  For example, a name
             //                    server may not wish to provide the
             //                    information to the particular requester,
             //                    or a name server may not wish to perform
             //                    a particular operation (e.g., zone
             //                    transfer) for particular data.
  ((RESEVERED))               // 6-15            Reserved for future use.
  )

class DNSHeader {
public:
  DNSHeader(std::uint16_t id,
    std::uint16_t flags,
    std::uint16_t qdCount,
    std::uint16_t anCount,
    std::uint16_t nsCount,
    std::uint16_t arCount) :
                             id_(id),
                             flags_(flags),
                             qdCount_(qdCount),
                             anCount_(anCount),
                             nsCount_(nsCount),
                             arCount_(arCount)
  {}

  DNSHeader() = default;

  class Builder;

  std::size_t parseData(const std::vector<std::uint8_t> &data) {
    id_ = combineBytes(data.at(0), data.at(1));
    flags_ = combineBytes(data.at(2), data.at(3));
    qdCount_ = combineBytes(data.at(4), data.at(5));
    anCount_ = combineBytes(data.at(6), data.at(7));
    nsCount_ = combineBytes(data.at(8), data.at(9));
    arCount_ = combineBytes(data.at(10), data.at(11));
    return 12;
  }

  std::uint16_t identificationNumber() const {
    return id_;
  }

  std::uint16_t numberOfQuestions() const {
    return qdCount_;
  }

  std::uint16_t numberOfAnswers() const {
    return anCount_;
  }

  std::uint16_t numberOfAuthorityRecords() const {
    return nsCount_;
  }

  std::uint16_t numberOfAdditionalRecords() const {
    return arCount_;
  }

  OPCode queryType() const {
    std::uint16_t opCode = flags_ >> OPCODE_FIELD;
    return static_cast<OPCode>(opCode);
  }

  Ra recursionAvailable() const {
    std::uint16_t ravailable = flags_ >> RD_FIELD;
    return static_cast<Ra>(ravailable);
  }

  RCode responseCode() const {
    std::uint16_t rcode = flags_ >> RCODE_FIELD;
    return static_cast<RCode>(rcode & 0x000F);
  }

  std::vector<std::uint8_t> data() const {
    std::vector<std::uint8_t> data{};
    data.push_back(id_ & 0xFF);
    data.push_back(id_ >> 8);
    data.push_back(flags_ & 0xFF);
    data.push_back(flags_ >> 8);
    data.push_back(qdCount_ & 0xFF);
    data.push_back(qdCount_ >> 8);
    data.push_back(anCount_ & 0xFF);
    data.push_back(anCount_ >> 8);
    data.push_back(nsCount_ & 0xFF);
    data.push_back(nsCount_ >> 8);
    data.push_back(arCount_ & 0xFF);
    data.push_back(arCount_ >> 8);
    return data;
  }

private:
  std::uint16_t id_;         // Identification number
  std::uint16_t flags_;      // Flags
  std::uint16_t qdCount_;    // Number of questions
  std::uint16_t anCount_;    // Number of answers
  std::uint16_t nsCount_;    // Number of authority records
  std::uint16_t arCount_;    // Number of additional records};
};


class DNSHeader::Builder {
public:
  DNSHeader::Builder& identifier(std::uint16_t identifier) { id_ = identifier; return *this; }
  DNSHeader::Builder& numberOfQuestions(std::uint16_t count) { qdCount_ = htons(count); return *this; }
  DNSHeader::Builder& specifiesQuery(OPCode opcode)  { opcode_ = opcode; return *this; }
  DNSHeader::Builder& recursionDesired(Rd recursion) { rd_ = recursion; return *this; }
  DNSHeader::Builder& truncation(Tc truncation) { tc_ = truncation; return *this; }

  DNSHeader build() const {
    std::uint16_t flags{};

    flags = flags | static_cast<std::uint16_t>(static_cast<std::uint16_t>(opcode_) << OPCODE_FIELD);
    flags = flags | static_cast<std::uint16_t>(static_cast<std::uint16_t>(tc_) << TC_FIELD);
    flags = flags | static_cast<std::uint16_t>(static_cast<std::uint16_t>(rd_) << RA_FIELD);

    return DNSHeader(id_, htons(flags), htons(qdCount_), 0, 0, 0);
  }

private:
  std::uint16_t id_{};
  std::uint16_t qdCount_{1};
  OPCode opcode_{OPCode::QUERY};
  Rd rd_{Rd::RECURSION_DESIRED};
  Tc tc_{Tc::NO_TRUNCATION};
};

// 3.2.2. TYPE values
//
// TYPE fields are used in resource records.  Note that these types are a
//      subset of QTYPEs.
//
// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
//
ENUM_CLASS(QType,
  ((A)(1))//              1 a host address
  ((NS)) //              2 an authoritative name server
  ((MD)) //              3 a mail destination (Obsolete - use MX)
  ((MF)) //              4 a mail forwarder (Obsolete - use MX)
  ((CNAME)) //           5 the canonical name for an alias
  ((SOA)) //             6 marks the start of a zone of authority
  ((MB)) //              7 a mailbox domain name (EXPERIMENTAL)
  ((MG)) //              8 a mail group member (EXPERIMENTAL)
  ((MR)) //              9 a mail rename domain name (EXPERIMENTAL)
  ((NIL)) //            10 a null RR (EXPERIMENTAL)
  ((WKS)) //            11 a well known service description
  ((PTR)) //            12 a domain name pointer
  ((HINFO))//           13 host information
  ((MINFO))//           14 mailbox or mail list information
  ((MX))//              15 mail exchange
  ((TXT))//             16 text strings
  ((AXFR)(252)) //     252 A request for a transfer of an entire zone
  ((MAILB))//          253 A request for mailbox-related records (MB, MG or MR)
  ((MAILA)) //         254 A request for mail agent RRs (Obsolete - see MX)
  ((ALL_RECORDS)) //   255 A request for all records
  )


// 3.2.3. QTYPE values
//
// QTYPE fields appear in the question part of a query.  QTYPES are a
//       superset of TYPEs, hence all TYPEs are valid QTYPEs.  In addition, the
//                                                      following QTYPEs are defined:
// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
//
ENUM_CLASS(QCLass,
  ((IN)(1)) //           1 the Internet
  ((CS)) //              2 the CSNET class (Obsolete - used only for examples in
        //            some obsolete RFCs)
  ((CH)) //              3 the CHAOS class
  ((HS)) //              4 Hesiod [Dyer 87]
  ((ANY_CLASS)(255)) //255 any class
  )

class DNSQuery {
public:
  DNSQuery(std::vector<uint8_t> qname,
    QType qtype,
    QCLass qclass) :
                     qname_{std::move(qname)},
                     qtype_{qtype},
                     qclass_{qclass}
  {}

  DNSQuery() = default;

  class Builder;

  std::string domainName() const {
    std::string dname{};
    int offset{};
    for(const auto& value : qname_) {
      if(offset == 0) {
        offset = value;
        dname.append(".");
      } else {
        dname.append(1, *reinterpret_cast<const char*>(&value));
        offset--;
      }
    }
    return dname;
  }

  std::size_t parseData(const std::vector<std::uint8_t> &data) {
    auto result = parseDomain(data);
    qname_ = std::get<0>(result);
    std::size_t offset = std::get<1>(result);
    qtype_ = static_cast<QType>(combineBytes(data.at(offset), data.at(offset + 1)));
    qclass_ = static_cast<QCLass>(combineBytes(data.at(offset + 2), data.at(offset + 3)));
    return offset + 4;
  }

  std::vector<std::uint8_t> data() const {
    std::vector<std::uint8_t> data = qname_;

    auto qtype = static_cast<std::uint16_t>(qtype_);
    data.push_back(static_cast<std::uint8_t>(qtype >> 8));
    data.push_back(static_cast<std::uint8_t>(qtype & 0xFF));

    auto qclass = static_cast<std::uint16_t>(qclass_);
    data.push_back(static_cast<std::uint8_t>(qclass >> 8));
    data.push_back(static_cast<std::uint8_t>(qclass & 0xFF));
    return data;
  }

private:
  std::vector<std::uint8_t> qname_{};
  QType qtype_{};
  QCLass qclass_{};
};

class DNSQuery::Builder {
public:
  DNSQuery::Builder& domainname(std::string qname) { qname_ = std::move(qname); return *this; }
  DNSQuery::Builder& typeOfQuery(QType qtype) { qtype_ = qtype; return *this; }
  DNSQuery::Builder& classOfQuery(QCLass qclass) { qclass_= qclass; return *this; }


  DNSQuery build() const
  {
    std::vector<uint8_t> name;

    using Tokenizer = boost::tokenizer<boost::char_separator<char>>;
    boost::char_separator<char> separator{"."};
    Tokenizer tokens{qname_, separator};
    for(const auto &t : tokens) {
      auto size = t.size();
      name.push_back(static_cast<uint8_t>(size));
      for(const auto &x : t) {
        name.push_back(static_cast<uint8_t>(x));
      }
    }
    name.push_back(0);

    return DNSQuery(name, qtype_, qclass_);
  }

private:
  std::string qname_{};
  QType qtype_{QType::A};
  QCLass qclass_{QCLass::IN};

};

class DNSResourceRecord {
public:
  DNSResourceRecord() = default;

  std::string rData() const {
    return rdata_;
  }

  std::uint32_t ttl() const {
    return ttl_;
  }

  std::size_t parseData(const std::vector<std::uint8_t> &data) {
    std::size_t offset{};
    std::uint16_t compression = combineBytes(data.at(offset), data.at(offset + 1));
    if(compression & 0xC000) {
      offset = 2;
      // TODO we assume it's a point ot qname
    } else {
      auto result = parseDomain(data);
      qname_ = std::get<0>(result);
      offset = std::get<1>(result);
    }
    qtype_ = static_cast<QType>(combineBytes(data.at(offset), data.at(offset + 1)));
    qclass_ = static_cast<QCLass>(combineBytes(data.at(offset + 2), data.at(offset + 3)));

    std::uint16_t ttlHigh = combineBytes(data.at(offset + 4), data.at(offset + 5));
    std::uint16_t ttlLow = combineBytes(data.at(offset + 6), data.at(offset + 7));
    ttl_ = combineTwoUint16s(ttlHigh, ttlLow);

    rdLength_ = combineBytes(data.at(offset + 8), data.at(offset + 9));

    switch(qtype_) {
    case QType::A:
    {
      rdata_.append(std::to_string(data.at(offset + 10)));
      rdata_.append(".");
      rdata_.append(std::to_string(data.at(offset + 11)));
      rdata_.append(".");
      rdata_.append(std::to_string(data.at(offset + 12)));
      rdata_.append(".");
      rdata_.append(std::to_string(data.at(offset + 13)));
    }
    break;
    default:
      std::cout << "Type " << format_QType(qtype_) << " not implemented yet!\n";
      break;
    }

    return offset + 13;
  }

private:
  std::vector<std::uint8_t> qname_{};
  QType qtype_{QType::A};
  QCLass qclass_{QCLass::IN};
  std::uint32_t ttl_{};
  std::uint16_t rdLength_{};

  std::string rdata_{};

};


int main(int argc, char* argv[])
{
  boost::program_options::options_description desc{"Options"};
  try
  {
    desc.add_options()
      ("help,h", "Help screen")
      ("dnsip,i", boost::program_options::value<std::string>()->required(), "IP from DoH DNS server")
      ("dnsdomain,n", boost::program_options::value<std::string>()->required(), "DNS domain name")
      ("dnsport,p", boost::program_options::value<unsigned short>()->default_value(PORT), "DNS DoH port")
      ("domain,d", boost::program_options::value<std::string>()->required(), "Domain name to resolv")
      ("uri,u", boost::program_options::value<std::string>()->default_value(DOH_URI), "DNS URI query")
      ("proxy,y", boost::program_options::value<std::string>(), "Proxy server")
      ("proxyport,o", boost::program_options::value<unsigned short>()->default_value(PROXY_PORT), "Proxy port")
      ("proxyuser,u", boost::program_options::value<std::string>(), "Proxy user")
      ("proxypasswd,w", boost::program_options::value<std::string>(), "Proxy password")
      ("type,t", boost::program_options::value<Type>()->required(), "GET or POST")
      ;

    boost::program_options::variables_map variables_map;
    store(parse_command_line(argc, argv, desc), variables_map);

    if (variables_map.count("help") != 0U) {
      std::cout << desc << '\n';
      return EXIT_SUCCESS;
    }

    notify(variables_map);

    auto domain = variables_map["domain"].as<std::string>();

    DNSHeader header = DNSHeader::Builder().build();
    DNSQuery query = DNSQuery::Builder().domainname(domain).build();



    auto dnsip = variables_map["dnsip"].as<std::string>();
    auto dnsport = variables_map["dnsport"].as<unsigned short>();
    auto dnsdomain = variables_map["dnsdomain"].as<std::string>();
    auto uri = variables_map["uri"].as<std::string>();

    boost::system::error_code ec;
    boost::asio::io_service io_service;

    boost::asio::ssl::context tls(boost::asio::ssl::context::sslv23);
    tls.set_default_verify_paths();
    // disabled to make development easier...
    // tls_ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    configure_tls_context(ec, tls);

    /*        tcp::socket socket{io_service};
            if(variables_map.count("proxy") != 0U) {
                auto proxy = variables_map["proxy"].as<std::string>();
                auto pport = variables_map["proxyport"].as<unsigned short>();

             socket.connect({boost::asio::ip::address_v4::from_string(proxy), pport});
         }
 */
    //        auto dnsEndpoint = boost::asio::ip::tcp::endpoint{boost::asio::ip::address::from_string(dnsip), dnsport};
    /*        if(variables_map.count("proxy") != 0U) {
                if(variables_map.count("proxyuser")) {
                    //auto user = variables_map["proxyuser"].as<std::string>();
                    //auto psswd = variables_map["proxypasswd"].as<std::string>();

                 throw std::system_error(ENOTSUP, std::generic_category(), "Proxy authentification not supported yet");
                 // TODO authentification
             }


              http::request<http::string_body> reqProxy{http::verb::connect, uri, VERSION};
              reqProxy.set(http::field::host, dnsdomain);
              reqProxy.set(http::field::user_agent, "Boost Beast DoH Client");
              reqProxy.set(http::field::content_type, "application/dns-message");

             http::write(socket, reqProxy);

              http::response<http::empty_body> resProxy;
              http::parser<false, http::empty_body> http_parser(resProxy);
              http_parser.skip(true);

             boost::beast::flat_buffer buffer;
             http::read(socket, buffer, http_parser);

              std::cout << "Target DNS server response: " << resProxy << std::endl;
          } else {
              stream.next_layer().connect(dnsEndpoint);
          }
  */

    auto headerData = header.data();
    auto queryData = query.data();


    session sess(io_service, tls, dnsip, std::to_string(dnsport));

    sess.on_connect([&sess,
                      &variables_map,
                      &uri,
                      &headerData,
                      &queryData](tcp::resolver::iterator /*endpoint_it*/) {
      boost::system::error_code ec;
      Type type = variables_map["type"].as<Type>();
      header_map hmap{};
      hmap.insert({"Content-type", {"application/dns-message", false}});

        const request* req{};
      if(type == Type::POST) {
        req = sess.submit(ec, "POST", uri, hmap);
      } else if(type == Type::GET) {
        auto base64HeaderData = Base64UrlEncode(std::string{headerData.begin(), headerData.end()});
        auto base64QueryData = Base64UrlEncode(std::string{queryData.begin(), queryData.end()});
        auto url = uri + "?dns=" + base64HeaderData + base64QueryData;

        req = sess.submit(ec, "GET", url, hmap);

        std::cout << "Request: " << std::endl;
        std::cout << "URI: " << url;
        std::cout << std::endl;
      }
      req->on_response([&sess](const response &res) {
        std::cout << "response received!" << std::endl;
        res.on_data([&sess](const uint8_t *data, std::size_t len) {
          std::cout <<  "Response: ";
          std::cout.write(reinterpret_cast<const char *>(data), len);
          std::cout << std::endl;

          std::vector<uint8_t> resBody;
          std::cout << "Response: " << std::endl;
          for(std::size_t x{}; x < len; x++) {
            resBody.emplace_back(data[x]);
            std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[x]) << ' ';
          }
          std::cout << std::endl;

          //std::cout << "0x00 0x00 0x01 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x03 0x77 0x77 0x77 0x07 0x65 0x78 0x61 0x6d 0x70 0x6c 0x65 0x03 0x63 0x6f 0x6d 0x00 0x00 0x01 0x00 0x01" << std::endl;

          // Process the DNS response here
          DNSHeader resHeader{};
          std::size_t offset = resHeader.parseData(resBody);
          std::cout << "Number of answers: " << resHeader.numberOfAnswers() << '\n';
          std::cout << "Response code: " << format_RCode(resHeader.responseCode()) << '\n';

          DNSQuery resQuery{};
          offset += resQuery.parseData(std::vector<std::uint8_t>(resBody.begin()+offset, resBody.end()));
          std::cout << "Domain name: " << resQuery.domainName() << '\n';

          DNSResourceRecord resRecord{};
          offset += resRecord.parseData(std::vector<std::uint8_t>(resBody.begin()+offset, resBody.end()));
          std::cout << "TTL: " << std::to_string(resRecord.ttl()) << '\n';
          std::cout << "RData: " << resRecord.rData() << '\n';


        });
      });

    });

    sess.on_error([](const boost::system::error_code &ec) {
      std::cerr << "error: " << ec.message() << std::endl;
    });

    io_service.run();
  } catch (const boost::program_options::required_option& e) {
    std::cerr << "Error: Required option '" << e.get_option_name() << "' is missing.\n";
    std::cout << desc << '\n';
    return EXIT_FAILURE;
  } catch (const boost::program_options::invalid_option_value& e) {
    std::cerr << "Error: Invalid value for option '" << e.get_option_name() << "'.\n";
    std::cout << desc << '\n';
    return EXIT_FAILURE;
  } catch (const boost::program_options::multiple_values& e) {
    std::cerr << "Error: Multiple values provided for option '" << e.get_option_name() << "'.\n";
    std::cout << desc << '\n';
    return EXIT_FAILURE;
  } catch (std::exception& e) {
    std::cerr << e.what() << '\n';
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << boost::current_exception_diagnostic_information();
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
