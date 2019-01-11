describe('adminNg.directives.adminNgEditableMultiValue', function () {
    var $compile, $rootScope, $timeout, element;

    beforeEach(module('adminNg'));
    beforeEach(module('shared/partials/editableMultiValue.html'));

    beforeEach(module(function ($provide) {
        var service = {
            configureFromServer: function () {},
            formatDate: function (val, date) { return date; },
            formatTime: function (val, date) { return date; }
        };
        $provide.value('Language', service);
    }));

    beforeEach(inject(function (_$rootScope_, _$compile_, _$timeout_) {
        $rootScope = _$rootScope_;
        $compile = _$compile_;
        $timeout = _$timeout_;
    }));

    beforeEach(function () {
        $rootScope.params = { value: ['Value 1', 'Value 2'] };
        $rootScope.save = jasmine.createSpy();
        element = $compile('<div admin-ng-editable-multi-value params="params" save="save"></div>')($rootScope);
        $rootScope.$digest();
    });

    it('creates an editable element', function () {
        expect(element).toContainElement('i.edit');
        expect(element.html()).toContain('Value 1');
        expect(element.html()).toContain('Value 2');
    });

    it('becomes editable when clicked', function () {
        expect(element.find('div').length).toBe(0);
        element.click();
        $timeout.flush();
        expect(element.find('div').length).toBe(1);
    });

    it('saves when adding values', function () {
        expect(element.scope().params.value).not.toContain('Value 3');

        element.click();
        element.find('input').val('Value 3').trigger('change');

        var enter = $.Event('keyup');
        enter.keyCode = 13;
        element.find('input').trigger(enter);

        expect($rootScope.save).toHaveBeenCalled();
        expect(element.scope().params.value).toContain('Value 3');
    });

    it('saves when removing values', function () {
        expect(element.scope().params.value).toContain('Value 1');

        element.click();
        element.find('span.ng-multi-value:first a').mousedown();

        expect($rootScope.save).toHaveBeenCalled();
        expect(element.scope().params.value).toContain('Value 2');
        expect(element.scope().params.value).not.toContain('Value 1');
    });

    describe('#leaveEditMode', function () {

        it('leaves edit mode', function () {
            var scope = element.find('ul').scope(); // the div & input elements don't exist when editMode = false
            scope.editMode = true;
            scope.data.value = 'edited';

            scope.leaveEditMode();

            expect(element.scope().params.value).not.toContain('edited')
            expect(scope.editMode).toBe(false);
            expect(scope.data.value).toEqual('');
        });
    });

    describe('#onBlur', function () {

        var scope;

        beforeEach(function () {
            scope = element.find('ul').scope();
            scope.editMode = true;
            scope.mixed = true;
            scope.data.value = 'edited';
        });

        it('saves and leaves edit mode', function () {
            scope.onBlur();

            expect(scope.editMode).toBe(false);
            expect(scope.data.value).toEqual('');
            expect(scope.params.value).toContain('edited')
        });
    })

    describe('#addValue', function () {

        it('does not save duplicate values', function () {
            var model = ['unique'];
            element.find('ul').scope().addValue(model, 'unique');
            expect(model).toEqual(['unique']);
        });
    });

    describe('#keyUp', function () {
        var event = { target: { value: 'a' } };
        var scope;

        beforeEach(function () {
            event.stopPropagation = jasmine.createSpy();
            scope = element.find('ul').scope();
            scope.editMode = true;

        });

        it('does nothing by default', function () {
            scope.keyUp(event);
            expect(scope.editMode).toBe(true);
        });

        it('stops propagation', function () {
            scope.keyUp(event);
            expect(event.stopPropagation).toHaveBeenCalled();
        });

        describe('when pressing ESC', function () {
            beforeEach(function () {
                event.keyCode = 27;
                scope.keyUp(event);
            });

            it('leaves edit mode', function () {
                expect(scope.editMode).toBe(false);
            });

            it('clears value', function () {
              expect(scope.data.value).toBe('');
            });
        });

        describe('when pressing ENTER', function () {
            beforeEach(function () {
                event.keyCode = 13;
                scope.keyUp(event);
            });

            it('does not leave edit mode', function () {
                expect(scope.editMode).toBe(true);
            });
        });
    });

    describe('#submit', function () {

        it('saves the value', function () {
            element.find('ul').scope().submit();
            expect($rootScope.save).toHaveBeenCalled();
        });
    });
});
