#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "policy_engine.hpp"

using namespace proxy_core;

TEST_CASE("PolicyEngine default-allows when no rules", "[policy]") {
    PolicyEngine engine;
    FlowDescriptor flow;
    flow.src_ip   = "192.168.1.1";
    flow.dst_host = "example.com";
    flow.dst_port = 80;
    REQUIRE(engine.evaluate(flow) == PolicyVerdict::Allow);
}

TEST_CASE("PolicyEngine deny rule matches CIDR", "[policy]") {
    PolicyEngine engine;
    PolicyRule rule;
    rule.id             = "deny-rfc1918";
    rule.src_ip_prefix  = "10.0.0.0/8";
    rule.verdict        = PolicyVerdict::Deny;
    rule.priority       = 10;
    engine.add_rule(rule);

    FlowDescriptor flow;
    flow.src_ip   = "10.1.2.3";
    flow.dst_host = "evil.com";
    flow.dst_port = 443;
    REQUIRE(engine.evaluate(flow) == PolicyVerdict::Deny);
}

TEST_CASE("PolicyEngine allow rule outside CIDR", "[policy]") {
    PolicyEngine engine;
    PolicyRule rule;
    rule.id            = "deny-rfc1918";
    rule.src_ip_prefix = "10.0.0.0/8";
    rule.verdict       = PolicyVerdict::Deny;
    engine.add_rule(rule);

    FlowDescriptor flow;
    flow.src_ip   = "172.16.0.1"; // NOT in 10.0.0.0/8
    flow.dst_host = "example.com";
    flow.dst_port = 80;
    REQUIRE(engine.evaluate(flow) == PolicyVerdict::Allow);
}

TEST_CASE("PolicyEngine glob matches dst_host", "[policy]") {
    PolicyEngine engine;
    PolicyRule rule;
    rule.id           = "block-ads";
    rule.dst_host_glob = "*.doubleclick.net";
    rule.verdict      = PolicyVerdict::Deny;
    engine.add_rule(rule);

    FlowDescriptor flow;
    flow.src_ip   = "1.2.3.4";
    flow.dst_host = "ad.doubleclick.net";
    flow.dst_port = 443;
    REQUIRE(engine.evaluate(flow) == PolicyVerdict::Deny);

    flow.dst_host = "example.com";
    REQUIRE(engine.evaluate(flow) == PolicyVerdict::Allow);
}

TEST_CASE("PolicyEngine port filter", "[policy]") {
    PolicyEngine engine;
    PolicyRule rule;
    rule.id        = "deny-23";
    rule.dst_ports = {23};
    rule.verdict   = PolicyVerdict::Deny;
    engine.add_rule(rule);

    FlowDescriptor flow;
    flow.src_ip   = "1.2.3.4";
    flow.dst_host = "anything";
    flow.dst_port = 23;
    REQUIRE(engine.evaluate(flow) == PolicyVerdict::Deny);

    flow.dst_port = 22;
    REQUIRE(engine.evaluate(flow) == PolicyVerdict::Allow);
}

TEST_CASE("PolicyEngine remove_rule", "[policy]") {
    PolicyEngine engine;
    PolicyRule rule;
    rule.id      = "r1";
    rule.verdict = PolicyVerdict::Deny;
    engine.add_rule(rule);
    engine.remove_rule("r1");

    FlowDescriptor flow{"1.2.3.4", 0, "x.com", 80, "tcp", ""};
    REQUIRE(engine.evaluate(flow) == PolicyVerdict::Allow);
}
