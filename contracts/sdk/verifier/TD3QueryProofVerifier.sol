// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract TD3QueryProofVerifier {
    // Scalar field size
    uint256 constant r =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax =
        10861103077745983971909492237210357861805822268651575043621346023994254984771;
    uint256 constant alphay =
        14617746139325962000670431014532132422429140259980041345800688108606853533339;
    uint256 constant betax1 =
        14551103016430195286299512452671693470328237279335021691932161000399225189934;
    uint256 constant betax2 =
        716437021663017040808856340562579223081367543869646934557008962069780128177;
    uint256 constant betay1 =
        18945869433760909644127265493546380854559826905562106437347111285982686821423;
    uint256 constant betay2 =
        547268328353844511275574008191302295639842019414855050237065482710037011078;
    uint256 constant gammax1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 =
        14467526384993582216805117267682201566398996185945792576789077739828318392942;
    uint256 constant deltax2 =
        9801007701717928826384734585170374434529268522813094357105103851337333735487;
    uint256 constant deltay1 =
        19591234640991119050200626158547464105167093562653999735034417649194657787513;
    uint256 constant deltay2 =
        13646262220144827025745130399711022365106264124981789836925939607870781681517;

    uint256 constant IC0x =
        18898201616048496936231890337094942803444918447266708521603815416069047558987;
    uint256 constant IC0y =
        970474762858678797976461569826328841913133628723340221516579361959851475269;

    uint256 constant IC1x =
        19328096265924181829385586583180979820753696958367919839447019385839122646314;
    uint256 constant IC1y =
        4016172047724162188068236849036470645946911690827074743248616525811441655005;

    uint256 constant IC2x =
        5704786571332563401374758716702320615025725452651246747972438871125377578681;
    uint256 constant IC2y =
        7193409487155560382208791506794363852205404714045999408258635718041087579933;

    uint256 constant IC3x =
        13365374754891957584871709669711056569064909744506377458047929373633196597081;
    uint256 constant IC3y =
        18676809712250977208046306198216364425998515790103777900110360629756416419637;

    uint256 constant IC4x =
        19943044134129907289211320399346711224789834734040056818705659057632821852854;
    uint256 constant IC4y =
        8007232482951304999851681621066394354855683491335029655048288734522602486347;

    uint256 constant IC5x =
        17855590130447934352706713576823259368139744316860379744122693305100070820069;
    uint256 constant IC5y =
        1592282803259024189144636740251001427454193989669122540351663387057053650927;

    uint256 constant IC6x =
        9379605843048395253210588324728855404005464343700263144330222581470652648014;
    uint256 constant IC6y =
        16266613473493134456808942068029768124656301115022522286359525889824268324866;

    uint256 constant IC7x =
        15150624877345764121488307402847350352411108903394022131396449351208151480672;
    uint256 constant IC7y =
        17923538502702421943504506377932726031057366150036670947568724418715890203931;

    uint256 constant IC8x =
        19795883473557279605390830794526534470453286125300653913931672087299206478089;
    uint256 constant IC8y =
        4198857438212232969612653787967409026211563560831838218867106760410460498006;

    uint256 constant IC9x =
        17834647143440128358613737829790956462974552925463679064157704150369763381926;
    uint256 constant IC9y =
        7330938198310289447281401990996689420269610453283695979833696557501746478049;

    uint256 constant IC10x =
        17445179090432707956301676127102745276238350519564137207295469613276221407609;
    uint256 constant IC10y =
        16309396859618179454233426418124924383599203095145379095547185426164773757179;

    uint256 constant IC11x =
        2465048047422890572491424245321650574208106487986821553824527178241462320818;
    uint256 constant IC11y =
        12552214116592853592141132930474837163103630390889906761065610852364764287496;

    uint256 constant IC12x =
        12544301525023269701593493873128925894700816750655262421971893566332030728744;
    uint256 constant IC12y =
        11315925474652262149303741227904779317610451369967002073236315575276611269089;

    uint256 constant IC13x =
        3604092359788691960520587653323441721705627866113951265979003508950131872577;
    uint256 constant IC13y =
        15353333084287967579236495003191651931348828093556497497668501804483376907096;

    uint256 constant IC14x =
        7211489686080144698975113674843973056648084240498563813092688511673937988652;
    uint256 constant IC14y =
        13674930024556377661197894488314826401383477115702812601412481816894878482752;

    uint256 constant IC15x =
        19546223955200506276916416460936816382782214750650254208914608820321531783323;
    uint256 constant IC15y =
        17625751362222160494478947162650976838869849643442119010590582692683703435966;

    uint256 constant IC16x =
        16385200996996702237313776015436609074446272192094232615997634585283114105443;
    uint256 constant IC16y =
        961534372394949302719610349504349722597842719712799471557734353384107957705;

    uint256 constant IC17x =
        10508694475769374038478708940985858087848123646879054364112853049844263070483;
    uint256 constant IC17y =
        8733772857432410674131320917008913064814411092416802049189237309956556278094;

    uint256 constant IC18x =
        11263045613344235644100224401504358936640021250670056271758506680382144190425;
    uint256 constant IC18y =
        20839288785237372111078781867223559395758725991615867551644908835363992349477;

    uint256 constant IC19x =
        6331887515458744530529888749888598520619430336317923247012011445223767086538;
    uint256 constant IC19y =
        13172823895086592364987852069184182225300264411018159220950244796686258570861;

    uint256 constant IC20x =
        15878464205764825851993121140751282318179831294338720823584767482786223530114;
    uint256 constant IC20y =
        19144598504458806080366192556306110306431266340850232192106443791769832870975;

    uint256 constant IC21x =
        15863811984586411372733239808983648634463303026137432231103596499315831334261;
    uint256 constant IC21y =
        6204760241123236475090846184746311367528202711725840187075579821016206437070;

    uint256 constant IC22x =
        12205825297003601967120867826337863376114815991020777852672014196359617920937;
    uint256 constant IC22y =
        17213371098788887279527870934561433694373928065225518536068597721059024859177;

    uint256 constant IC23x =
        16663862190499165116459708954335045729407361196498741212750278034953495802171;
    uint256 constant IC23y =
        6083220441876287051483037340428819940857254176009474183276427950563152617391;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[23] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))

                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))

                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))

                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))

                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))

                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))

                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))

                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))

                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))

                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))

                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))

                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))

                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))

                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))

                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))

                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))

                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))

                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))

                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            checkField(calldataload(add(_pubSignals, 128)))

            checkField(calldataload(add(_pubSignals, 160)))

            checkField(calldataload(add(_pubSignals, 192)))

            checkField(calldataload(add(_pubSignals, 224)))

            checkField(calldataload(add(_pubSignals, 256)))

            checkField(calldataload(add(_pubSignals, 288)))

            checkField(calldataload(add(_pubSignals, 320)))

            checkField(calldataload(add(_pubSignals, 352)))

            checkField(calldataload(add(_pubSignals, 384)))

            checkField(calldataload(add(_pubSignals, 416)))

            checkField(calldataload(add(_pubSignals, 448)))

            checkField(calldataload(add(_pubSignals, 480)))

            checkField(calldataload(add(_pubSignals, 512)))

            checkField(calldataload(add(_pubSignals, 544)))

            checkField(calldataload(add(_pubSignals, 576)))

            checkField(calldataload(add(_pubSignals, 608)))

            checkField(calldataload(add(_pubSignals, 640)))

            checkField(calldataload(add(_pubSignals, 672)))

            checkField(calldataload(add(_pubSignals, 704)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
