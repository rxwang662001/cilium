// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build privileged_tests
// +build privileged_tests

package egressmap

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type EgressMapTestSuite struct{}

var _ = Suite(&EgressMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *EgressMapTestSuite) SetUpSuite(c *C) {
	bpf.CheckOrMountFS("")
	err := bpf.ConfigureResourceLimits()
	c.Assert(err, IsNil)
}

func (k *EgressMapTestSuite) TestEgressMap(c *C) {
	err := initEgressPolicyMap("test_egress_policy_v4", true)
	c.Assert(err, IsNil)
	defer EgressPolicyMap.Unpin()

	sourceIP1 := net.ParseIP("1.1.1.1")
	sourceIP2 := net.ParseIP("1.1.1.2")

	_, destCIDR1, err := net.ParseCIDR("2.2.1.0/24")
	c.Assert(err, IsNil)
	_, destCIDR2, err := net.ParseCIDR("2.2.2.0/24")
	c.Assert(err, IsNil)

	egressIP1 := net.ParseIP("3.3.3.1")
	egressIP2 := net.ParseIP("3.3.3.2")

	err = ApplyEgressPolicy(sourceIP1, *destCIDR1, egressIP1, egressIP1)
	c.Assert(err, IsNil)

	err = ApplyEgressPolicy(sourceIP2, *destCIDR2, egressIP2, egressIP2)
	c.Assert(err, IsNil)

	val, err := EgressPolicyMap.Lookup(sourceIP1, *destCIDR1)
	c.Assert(err, IsNil)

	c.Assert(val.EgressIP.IP().Equal(egressIP1), Equals, true)
	c.Assert(val.GatewayIP.IP().Equal(egressIP1), Equals, true)

	val, err = EgressPolicyMap.Lookup(sourceIP2, *destCIDR2)
	c.Assert(err, IsNil)

	c.Assert(val.EgressIP.IP().Equal(egressIP2), Equals, true)
	c.Assert(val.GatewayIP.IP().Equal(egressIP2), Equals, true)
}
